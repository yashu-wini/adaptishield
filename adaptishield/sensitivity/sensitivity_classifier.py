# sensitivity/sensitivity_classifier.py
"""
Sensitivity Engine: Classifies document-level risk and per-entity sensitivity.

Risk Formula:
  RiskScore = Σ (SensitivityWeight_i × Confidence_i)
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from configs.pii_config import PII_SENSITIVITY_WEIGHTS, RISK_LEVELS, ANONYMIZATION_POLICY


class SensitivityClassifier:
    """
    Assigns sensitivity levels to detected PII entities
    and computes an overall document risk score.
    """

    def classify_entity(self, detection: dict) -> dict:
        """Add sensitivity_weight and sensitivity_level to a detection."""
        entity_type = detection["entity_type"]
        weight = PII_SENSITIVITY_WEIGHTS.get(entity_type, 10)
        effective_score = weight * detection["confidence"]

        # Determine entity-level sensitivity
        if effective_score >= 70:
            level = "CRITICAL"
        elif effective_score >= 40:
            level = "HIGH"
        elif effective_score >= 20:
            level = "MEDIUM"
        else:
            level = "LOW"

        updated = detection.copy()
        updated["sensitivity_weight"] = weight
        updated["effective_score"] = round(effective_score, 2)
        updated["sensitivity_level"] = level
        updated["anonymization_strategy"] = ANONYMIZATION_POLICY[level]
        return updated

    def classify_document(self, detections: list[dict]) -> dict:
        """
        Compute overall document risk score from all detections.
        Returns risk classification and summary statistics.
        """
        if not detections:
            return {
                "risk_score": 0.0,
                "risk_level": "LOW",
                "entity_count": 0,
                "entity_breakdown": {},
                "high_risk_entities": [],
                "recommendations": ["No PII detected. Document appears safe."]
            }

        # Score each entity
        classified = [self.classify_entity(d) for d in detections]

        # Document-level risk = sum of (weight × confidence)
        risk_score = sum(d["sensitivity_weight"] * d["confidence"] for d in classified)

        # Determine risk level
        risk_level = "LOW"
        for level, (low, high) in RISK_LEVELS.items():
            if low <= risk_score < high:
                risk_level = level
                break

        # Entity breakdown
        from collections import Counter
        entity_counts = Counter(d["entity_type"] for d in classified)

        # High-risk entities (CRITICAL or HIGH)
        high_risk = [
            d["entity_type"] for d in classified
            if d["sensitivity_level"] in ("CRITICAL", "HIGH")
        ]

        # Recommendations
        recommendations = self._generate_recommendations(risk_level, entity_counts, high_risk)

        return {
            "risk_score": round(risk_score, 2),
            "risk_level": risk_level,
            "entity_count": len(classified),
            "entity_breakdown": dict(entity_counts),
            "classified_entities": classified,
            "high_risk_entities": list(set(high_risk)),
            "recommendations": recommendations
        }

    def _generate_recommendations(
        self,
        risk_level: str,
        entity_counts: dict,
        high_risk: list
    ) -> list[str]:
        recs = []

        if risk_level == "CRITICAL":
            recs.append("⚠️  CRITICAL: Document contains highly sensitive PII. Immediate redaction required.")
        elif risk_level == "HIGH":
            recs.append("🔴 HIGH RISK: Document contains sensitive PII. Tokenization/redaction recommended.")
        elif risk_level == "MEDIUM":
            recs.append("🟡 MEDIUM RISK: PII detected. Masking recommended before sharing.")
        else:
            recs.append("🟢 LOW RISK: Minor PII detected. Apply masking as a precaution.")

        if "AADHAAR" in entity_counts:
            recs.append("Aadhaar numbers detected — comply with UIDAI guidelines (full redaction required).")
        if "PAN" in entity_counts:
            recs.append("PAN numbers detected — comply with Indian IT Act data handling norms.")
        if "CREDIT_CARD" in entity_counts:
            recs.append("Credit card data detected — PCI-DSS compliance mandatory.")
        if "PASSWORD" in entity_counts:
            recs.append("🚨 PASSWORDS DETECTED — Redact immediately. Do not transmit or store.")
        if "MEDICAL_RECORD" in entity_counts:
            recs.append("Medical data detected — HIPAA/DPDP Act compliance required.")

        return recs
