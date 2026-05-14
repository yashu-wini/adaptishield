# detection/transformer_detector.py

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Map transformer NER labels to our PII schema
NER_LABEL_MAP = {
    "PER":    "NAME",
    "PERSON": "NAME",
    "DATE":   "DATE_OF_BIRTH",
    "TIME":   "DATE_OF_BIRTH",
    "MONEY":  "CREDIT_CARD",
}


class TransformerDetector:
    """
    Hugging Face transformer-based NER for contextual PII detection.
    Primary model: dslim/bert-base-NER (fast, production-ready)
    Can swap to microsoft/deberta-v3-base for higher accuracy.
    """

    def __init__(self, model_name: str = "dslim/bert-base-NER"):
        self.model_name = model_name
        self._pipeline = None

    def _load(self):
        """Lazy-load the model on first use."""
        if self._pipeline is None:
            try:
                from transformers import pipeline
                logger.info(f"[TransformerDetector] Loading model: {self.model_name}")
                self._pipeline = pipeline(
                    "ner",
                    model=self.model_name,
                    aggregation_strategy="simple",
                    device=-1  # CPU; change to 0 for GPU
                )
                logger.info("[TransformerDetector] Model loaded successfully.")
            except Exception as e:
                logger.error(f"[TransformerDetector] Failed to load model: {e}")
                self._pipeline = None

    def detect(self, text: str) -> list[dict]:
        """Detect named entities using transformer NER."""
        self._load()
        if self._pipeline is None:
            logger.warning("[TransformerDetector] Pipeline unavailable, returning empty.")
            return []

        # Chunk long texts (transformers have 512 token limit)
        chunks = self._chunk_text(text, max_chars=450)
        detections = []
        offset = 0

        for chunk in chunks:
            try:
                results = self._pipeline(chunk)
                logger.debug(f"[TransformerDetector] Raw results for chunk ({len(chunk)} chars): {results}")
                for ent in results:
                    label = ent.get("entity_group", "")
                    pii_type = NER_LABEL_MAP.get(label)
                    if not pii_type:
                        logger.debug(f"[TransformerDetector] Skipping unmapped label: {label}")
                        continue

                    score = float(ent.get("score", 0))
                    if score < 0.50:
                        logger.debug(f"[TransformerDetector] Skipping low-score entity: {label}={ent.get('word', '')} score={score}")
                        continue

                    detections.append({
                        "entity_type": pii_type,
                        "value": ent["word"].strip(),
                        "start": ent["start"] + offset,
                        "end": ent["end"] + offset,
                        "confidence": round(score, 4),
                        "source": "transformer"
                    })
            except Exception as e:
                logger.warning(f"[TransformerDetector] Error on chunk: {e}")

            offset += len(chunk)

        logger.info(f"[TransformerDetector] Detected {len(detections)} entities from {len(chunks)} chunk(s)")
        return detections

    def _chunk_text(self, text: str, max_chars: int = 450) -> list[str]:
        """Split text into overlapping chunks to handle long documents."""
        if len(text) <= max_chars:
            return [text]
        chunks = []
        words = text.split()
        current = []
        length = 0
        for word in words:
            if length + len(word) > max_chars:
                chunks.append(" ".join(current))
                current = current[-10:]  # Small overlap
                length = sum(len(w) + 1 for w in current)
            current.append(word)
            length += len(word) + 1
        if current:
            chunks.append(" ".join(current))
        return chunks
