# detection/spacy_detector.py

import logging

logger = logging.getLogger(__name__)

SPACY_LABEL_MAP = {
    "PERSON":   "NAME",
    "DATE":     "DATE_OF_BIRTH",
    "MONEY":    "CREDIT_CARD",
    "CARDINAL": None,  # Skip generic numbers
    "NORP":     None,  # Skip nationalities/groups
}


class SpacyDetector:
    """
    spaCy-based NER detector.
    Fast, good for named entities: names, organizations, locations.
    Used as a supplementary signal alongside the transformer.
    """

    # Fallback model order: try larger models first, fall back to smaller
    FALLBACK_MODELS = ["en_core_web_lg", "en_core_web_md", "en_core_web_sm"]

    def __init__(self, model: str = "en_core_web_lg"):
        self.model_name = model
        self._nlp = None
        self._load_attempted = False

    def _load(self):
        if self._nlp is not None or self._load_attempted:
            return

        self._load_attempted = True
        try:
            import spacy

            # Try the requested model first, then fallbacks
            models_to_try = [self.model_name] + [
                m for m in self.FALLBACK_MODELS if m != self.model_name
            ]

            for model in models_to_try:
                try:
                    self._nlp = spacy.load(model)
                    self.model_name = model
                    logger.info(f"[SpacyDetector] Loaded {model}")
                    return
                except OSError:
                    logger.debug(f"[SpacyDetector] Model {model} not available, trying next...")

            logger.warning(
                f"[SpacyDetector] No spaCy model found. "
                f"Run: python -m spacy download en_core_web_sm"
            )
        except ImportError:
            logger.warning("[SpacyDetector] spaCy is not installed.")

    def detect(self, text: str) -> list[dict]:
        self._load()
        if self._nlp is None:
            return []

        doc = self._nlp(text)
        detections = []

        for ent in doc.ents:
            pii_type = SPACY_LABEL_MAP.get(ent.label_)
            if not pii_type:
                continue

            detections.append({
                "entity_type": pii_type,
                "value": ent.text.strip(),
                "start": ent.start_char,
                "end": ent.end_char,
                "confidence": 0.78,  # spaCy doesn't give per-entity scores
                "source": "spacy"
            })

        return detections
