# detection/spacy_detector.py

import logging

logger = logging.getLogger(__name__)

SPACY_LABEL_MAP = {
    "PERSON":   "NAME",
    "ORG":      "ORGANIZATION",
    "GPE":      "LOCATION",
    "LOC":      "LOCATION",
    "FAC":      "LOCATION",
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

    def __init__(self, model: str = "en_core_web_lg"):
        self.model_name = model
        self._nlp = None

    def _load(self):
        if self._nlp is None:
            try:
                import spacy
                self._nlp = spacy.load(self.model_name)
                logger.info(f"[SpacyDetector] Loaded {self.model_name}")
            except OSError:
                logger.warning(f"[SpacyDetector] Model {self.model_name} not found. "
                                f"Run: python -m spacy download {self.model_name}")
                self._nlp = None

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
