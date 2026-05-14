# context/confidence_engine.py
"""
Confidence Engine: Final recalibration of confidence scores.
Applies document-level analysis and entity co-occurrence boosts.
"""

from collections import Counter


class ConfidenceEngine:
    """
    Recalibrates confidence scores after context validation.
    Considers:
    - Frequency of same entity appearing multiple times
    - Co-occurrence of related PII (e.g., name + email = higher confidence)
    - Document type signals
    """

    # Co-occurrence boosts: if entity A and B both found, boost B's confidence
    CO_OCCURRENCE_BOOSTS = {
        # Identity / Basic Profile
        frozenset(["NAME", "EMAIL"]): 0.05,
        frozenset(["NAME", "PHONE"]): 0.05,
        frozenset(["NAME", "ADDRESS"]): 0.07,
        frozenset(["NAME", "DATE_OF_BIRTH"]): 0.08,
        frozenset(["NAME", "AGE"]): 0.04,
        frozenset(["NAME", "GENDER"]): 0.03,

        # Government IDs
        frozenset(["NAME", "AADHAAR"]): 0.10,
        frozenset(["NAME", "PAN"]): 0.10,
        frozenset(["NAME", "PASSPORT"]): 0.10,
        frozenset(["NAME", "VOTER_ID"]): 0.09,
        frozenset(["NAME", "DRIVING_LICENSE"]): 0.09,

        # Financial
        frozenset(["NAME", "CREDIT_CARD"]): 0.08,
        frozenset(["NAME", "BANK_ACCOUNT"]): 0.08,
        frozenset(["BANK_ACCOUNT", "IFSC_CODE"]): 0.12,
        frozenset(["NAME", "UPI_ID"]): 0.06,
        frozenset(["PHONE", "UPI_ID"]): 0.08,

    }

    def recalibrate(self, detections: list[dict]) -> list[dict]:
        """Apply final confidence recalibration."""
        if not detections:
            return detections

        entity_types_present = set(d["entity_type"] for d in detections)

        # Determine applicable co-occurrence boosts
        applicable_boosts = {}
        for entity_pair, boost in self.CO_OCCURRENCE_BOOSTS.items():
            if entity_pair.issubset(entity_types_present):
                for entity in entity_pair:
                    applicable_boosts[entity] = applicable_boosts.get(entity, 0) + boost

        # Count entity occurrences
        entity_counts = Counter(d["entity_type"] for d in detections)

        recalibrated = []
        for det in detections:
            new_det = det.copy()
            conf = det["confidence"]

            # Apply co-occurrence boost
            boost = applicable_boosts.get(det["entity_type"], 0)
            conf = min(1.0, conf + boost)

            # Frequency boost (seeing same entity type multiple times is more suspicious)
            count = entity_counts[det["entity_type"]]
            if count > 3:
                conf = min(1.0, conf * 1.05)

            new_det["confidence"] = round(conf, 4)
            recalibrated.append(new_det)

        return recalibrated
