# context/quasi_identifier_engine.py
"""
Quasi-Identifier Correlation Engine
=====================================
Evaluates re-identification risk by analyzing **combinations** of detected
entities rather than individual entities in isolation.

Research Basis:
  "A scaling law to model the effectiveness of identification techniques"
  — Rocher et al. (2025)

  Key insight: individually non-sensitive fields (Name, DOB, ZIP) become
  highly identifying when combined. 15 demographic attributes can uniquely
  re-identify 99.98% of Americans.

Risk Model:
  final_risk = Σ(entity_risk) + Σ(correlation_risk)

  correlation_risk is computed from known dangerous quasi-identifier
  combinations found in the document.
"""

from typing import Dict, List, Set, Tuple
from itertools import combinations


class QuasiIdentifierEngine:
    """
    Detects dangerous combinations of quasi-identifiers that could enable
    re-identification attacks, even after individual anonymization.
    """

    # ── Quasi-Identifier Combination Risk Table ─────────────────
    # Each tuple defines: (entity_set, risk_label, correlation_score, description)
    CORRELATION_RULES: List[Tuple[frozenset, str, float, str]] = [
        # Two-entity combinations
        (frozenset(["NAME", "DATE_OF_BIRTH"]),
         "MEDIUM", 25.0,
         "Name + DOB can narrow identity significantly"),

        (frozenset(["NAME", "PHONE"]),
         "HIGH", 35.0,
         "Name + Phone is often uniquely identifying"),

        (frozenset(["NAME", "EMAIL"]),
         "HIGH", 30.0,
         "Name + Email provides direct contact identity"),

        (frozenset(["NAME", "ADDRESS"]),
         "HIGH", 40.0,
         "Name + Address is a classic re-identification pair"),

        (frozenset(["PAN", "NAME"]),
         "HIGH", 45.0,
         "PAN + Name enables financial identity linkage"),

        (frozenset(["AADHAAR", "NAME"]),
         "CRITICAL", 60.0,
         "Aadhaar + Name is a unique national identifier pair"),

        (frozenset(["AADHAAR", "PHONE"]),
         "CRITICAL", 55.0,
         "Aadhaar + Phone is linked via UIDAI verification"),

        (frozenset(["EMAIL", "PHONE"]),
         "HIGH", 35.0,
         "Email + Phone enables cross-platform identity linking"),

        (frozenset(["EMAIL", "PASSWORD"]),
         "CRITICAL", 70.0,
         "Email + Password is a direct credential exposure"),

        (frozenset(["CREDIT_CARD", "NAME"]),
         "CRITICAL", 55.0,
         "Credit card + Name enables financial fraud"),

        (frozenset(["BANK_ACCOUNT", "IFSC_CODE"]),
         "CRITICAL", 60.0,
         "Account + IFSC fully identifies a bank account"),

        (frozenset(["BANK_ACCOUNT", "NAME"]),
         "HIGH", 45.0,
         "Account + Name enables targeted financial fraud"),

        (frozenset(["UPI_ID", "PHONE"]),
         "HIGH", 40.0,
         "UPI + Phone identifies fintech transaction source"),

        (frozenset(["CREDIT_CARD", "DATE"]),
         "HIGH", 35.0,
         "Card + Transaction date narrows transaction identity"),

        # Three-entity combinations (high re-identification risk)
        (frozenset(["NAME", "DATE_OF_BIRTH", "PINCODE"]),
         "CRITICAL", 65.0,
         "Name + DOB + PIN uniquely identifies per Rocher et al."),

        (frozenset(["NAME", "AGE", "LOCATION"]),
         "HIGH", 40.0,
         "Name + Age + Location is a strong quasi-ID triplet"),

        (frozenset(["PAN", "BANK_ACCOUNT", "NAME"]),
         "CRITICAL", 75.0,
         "PAN + Account + Name is full financial identity"),

        (frozenset(["AADHAAR", "PAN", "NAME"]),
         "CRITICAL", 80.0,
         "Aadhaar + PAN + Name is complete Indian identity"),
    ]

    def analyze(self, detections: List[Dict]) -> Dict:
        """
        Analyze detected entities for dangerous quasi-identifier combinations.

        Args:
            detections: List of entity dicts with 'entity_type' key.

        Returns:
            dict with:
                - correlation_risks (list): Matched combination risks
                - total_correlation_score (float): Sum of all correlation scores
                - re_identification_level (str): Overall re-ID risk level
                - recommendations (list): Mitigation advice
        """
        entity_types_present: Set[str] = set(d["entity_type"] for d in detections)

        matched_risks = []
        total_correlation_score = 0.0

        for required_set, risk_label, score, description in self.CORRELATION_RULES:
            if required_set.issubset(entity_types_present):
                matched_risks.append({
                    "combination": sorted(required_set),
                    "risk_level": risk_label,
                    "correlation_score": score,
                    "description": description,
                })
                total_correlation_score += score

        # Determine overall re-identification risk level
        if total_correlation_score >= 100:
            re_id_level = "CRITICAL"
        elif total_correlation_score >= 50:
            re_id_level = "HIGH"
        elif total_correlation_score >= 20:
            re_id_level = "MEDIUM"
        else:
            re_id_level = "LOW"

        # Generate recommendations
        recommendations = self._generate_recommendations(
            matched_risks, re_id_level, entity_types_present
        )

        return {
            "correlation_risks": matched_risks,
            "total_correlation_score": round(total_correlation_score, 2),
            "re_identification_level": re_id_level,
            "quasi_id_combinations_found": len(matched_risks),
            "recommendations": recommendations,
        }

    def get_correlation_score(self, detections: List[Dict]) -> float:
        """
        Quick method to get just the total correlation score.
        Used by sensitivity_classifier to add to entity-level risk.
        """
        result = self.analyze(detections)
        return result["total_correlation_score"]

    def _generate_recommendations(
        self,
        matched_risks: List[Dict],
        re_id_level: str,
        entity_types: Set[str]
    ) -> List[str]:
        recs = []

        if re_id_level == "CRITICAL":
            recs.append(
                "⚠️  CRITICAL RE-IDENTIFICATION RISK: Multiple quasi-identifier "
                "combinations detected. Full redaction of identifying fields required."
            )
        elif re_id_level == "HIGH":
            recs.append(
                "🔴 HIGH RE-ID RISK: Entity combinations could enable identity "
                "reconstruction. Apply k-anonymity or suppression."
            )
        elif re_id_level == "MEDIUM":
            recs.append(
                "🟡 MODERATE RE-ID RISK: Some quasi-identifier pairs found. "
                "Consider generalization to reduce linkability."
            )

        # Specific advice
        critical_combos = [r for r in matched_risks if r["risk_level"] == "CRITICAL"]
        for combo in critical_combos[:3]:  # Top 3 critical combos
            entities = " + ".join(combo["combination"])
            recs.append(f"  → {entities}: {combo['description']}")

        if {"AADHAAR", "PAN"}.issubset(entity_types):
            recs.append(
                "Aadhaar + PAN detected — per UIDAI and IT Act guidelines, "
                "these must never appear together in shared documents."
            )

        if {"EMAIL", "PASSWORD"}.issubset(entity_types):
            recs.append(
                "🚨 Credential pair (Email + Password) detected — "
                "immediate suppression required. Potential data breach."
            )

        return recs
