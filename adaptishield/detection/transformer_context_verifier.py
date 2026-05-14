# detection/transformer_context_verifier.py
"""
Transformer Context Verifier — Optional deep semantic re-scoring.
=================================================================
Uses zero-shot NLI (Natural Language Inference) to verify whether
regex/spaCy-detected entities are truly PII in their full sentence context.

Architecture:
    Regex/spaCy generate candidates → Context Validator filters (fast, deterministic)
    → TransformerContextVerifier re-scores survivors using full sentence understanding.

This is OPTIONAL. The pipeline works perfectly without it (22/22 edge cases pass
with just the Context Validator). The verifier adds deeper semantic understanding
for ambiguous cases that keyword-based checks can't resolve.

Example:
    "I have reached 7000138006 followers, please reach out to me"
    → Regex detects 7000138006 as PHONE (starts with 7, 10 digits)
    → Context Validator may miss this (no preceding label, no negative keyword)
    → TransformerContextVerifier reads the full sentence and classifies:
        "This text contains a phone number" → 0.25 (low)
        "This text contains a count or metric" → 0.75 (high)
      → Penalizes confidence → entity rejected
"""

import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


class TransformerContextVerifier:
    """
    Zero-shot NLI-based contextual verifier for PII candidates.

    Uses a pre-trained NLI model to classify whether each candidate entity
    is truly PII in its sentence context. Only processes entities that
    would benefit from deep semantic analysis (numeric/ambiguous types).

    The system degrades gracefully: if the model can't be loaded,
    all entities pass through unchanged.
    """

    # Entity types that benefit from transformer verification.
    # These are structurally ambiguous (a 10-digit number could be phone OR count).
    # Types like EMAIL (has @domain) or PASSWORD (captured with keyword) don't need this.
    VERIFIABLE_TYPES = {
        "PHONE", "CREDIT_CARD", "AADHAAR", "PINCODE",
        "BANK_ACCOUNT", "PAN",
    }

    # PII hypothesis per entity type (what zero-shot tries to confirm)
    ENTITY_HYPOTHESES = {
        "PHONE":        "This text contains someone's personal phone number or contact number",
        "CREDIT_CARD":  "This text contains a credit card number or payment card number",
        "AADHAAR":      "This text contains an Aadhaar identification number",
        "PAN":          "This text contains a PAN card number or tax identification number",
        "BANK_ACCOUNT": "This text contains a bank account number",
        "PINCODE":      "This text contains a postal PIN code or ZIP code for an address",
    }

    # Counter-hypothesis (what zero-shot tries to confirm as NOT PII)
    NON_PII_HYPOTHESIS = (
        "This text contains a general number, count, statistic, "
        "version number, identifier, or measurement that is not "
        "sensitive personal information"
    )

    def __init__(self, model_name: str = "facebook/bart-large-mnli"):
        """
        Args:
            model_name: HuggingFace model for zero-shot classification.
                        Default: facebook/bart-large-mnli (most accurate, ~1.6GB)
                        Lighter alternative: typeform/distilbert-base-uncased-mnli (~250MB)
        """
        self.model_name = model_name
        self._classifier = None
        self._available = None
        self._load_attempted = False

    def _load(self):
        """Lazy-load the zero-shot classification model on first use."""
        if self._load_attempted:
            return
        self._load_attempted = True

        try:
            from transformers import pipeline as hf_pipeline
            logger.info(f"[TransformerContextVerifier] Loading model: {self.model_name}")
            self._classifier = hf_pipeline(
                "zero-shot-classification",
                model=self.model_name,
                device=-1  # CPU; change to 0 for GPU
            )
            self._available = True
            logger.info("[TransformerContextVerifier] Model loaded successfully.")
        except Exception as e:
            logger.warning(
                f"[TransformerContextVerifier] Model unavailable ({e}). "
                f"Entities will pass through without transformer verification."
            )
            self._available = False

    @property
    def is_available(self) -> bool:
        """Check if the verifier model is loaded and ready."""
        if not self._load_attempted:
            self._load()
        return bool(self._available)

    def verify_entities(
        self,
        entities: List[Dict],
        text: str
    ) -> List[Dict]:
        """
        Re-score entities using transformer zero-shot classification.

        For each verifiable entity, extracts its full sentence and asks:
        "Is [value] a [PII type] in this sentence, or a general number/metric?"

        Args:
            entities: List of validated entity dicts from Context Validator.
            text: The full document text.

        Returns:
            Same list with confidence values adjusted based on transformer verdict.
        """
        if not self.is_available:
            return entities

        verified = []
        verify_count = 0

        for entity in entities:
            entity_type = entity["entity_type"]

            # Skip types that don't need verification
            if entity_type not in self.VERIFIABLE_TYPES:
                verified.append(entity)
                continue

            # Skip very high confidence (regex structural validation is definitive)
            if entity.get("confidence", 0) >= 0.98:
                verified.append(entity)
                continue

            # Extract the sentence containing the entity
            sentence = self._extract_sentence(text, entity["start"], entity["end"])
            if not sentence or len(sentence) < 5:
                verified.append(entity)
                continue

            # Zero-shot classify: PII vs non-PII
            pii_hypothesis = self.ENTITY_HYPOTHESES.get(entity_type)
            if not pii_hypothesis:
                verified.append(entity)
                continue

            try:
                result = self._classifier(
                    sentence,
                    candidate_labels=[pii_hypothesis, self.NON_PII_HYPOTHESIS],
                    multi_label=False
                )

                # Extract PII score
                pii_score = 0.5
                for label, score in zip(result["labels"], result["scores"]):
                    if label == pii_hypothesis:
                        pii_score = score
                        break

                verify_count += 1
                updated = entity.copy()
                confidence = entity["confidence"]
                notes = list(entity.get("context_notes", []))

                if pii_score < 0.35:
                    # Transformer strongly says NOT PII → heavy penalty
                    updated["confidence"] = round(confidence * 0.15, 4)
                    notes.append(f"transformer_rejects:pii={pii_score:.2f}")
                elif pii_score < 0.50:
                    # Transformer leans NOT PII → moderate penalty
                    updated["confidence"] = round(confidence * 0.40, 4)
                    notes.append(f"transformer_uncertain:pii={pii_score:.2f}")
                elif pii_score >= 0.70:
                    # Transformer strongly confirms → slight boost
                    boost = 1.0 + (pii_score - 0.70) * 0.3  # up to ×1.09
                    updated["confidence"] = round(min(1.0, confidence * boost), 4)
                    notes.append(f"transformer_confirms:pii={pii_score:.2f}")
                else:
                    # Transformer is neutral (0.50-0.70) → no change
                    notes.append(f"transformer_neutral:pii={pii_score:.2f}")

                updated["context_notes"] = notes
                verified.append(updated)

            except Exception as e:
                logger.warning(f"[TransformerContextVerifier] Error verifying {entity_type}: {e}")
                verified.append(entity)

        if verify_count > 0:
            logger.info(
                f"[TransformerContextVerifier] Verified {verify_count} entities "
                f"via zero-shot NLI"
            )

        return verified

    def _extract_sentence(self, text: str, start: int, end: int) -> str:
        """
        Extract the full sentence containing the entity.
        Uses sentence-ending punctuation (.!?\\n) as boundaries.
        Falls back to a 300-char window if no boundary is found.
        """
        # Find sentence start (search backwards)
        sentence_start = start
        for i in range(start - 1, max(0, start - 300) - 1, -1):
            if text[i] in '.!?\n':
                sentence_start = i + 1
                break
        else:
            sentence_start = max(0, start - 300)

        # Find sentence end (search forwards)
        sentence_end = end
        for i in range(end, min(len(text), end + 300)):
            if text[i] in '.!?\n':
                sentence_end = i + 1
                break
        else:
            sentence_end = min(len(text), end + 300)

        return text[sentence_start:sentence_end].strip()
