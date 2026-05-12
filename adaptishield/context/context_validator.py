# context/context_validator.py
"""
Context Validator: Analyzes surrounding text to validate PII detections.
Reduces false positives by checking semantic context.

Example: "12345 Oak Street" is an ADDRESS, not a bank account number.
Example: "Call +91-9876543210 for support" → phone in support context → valid but lower sensitivity
"""

import re
from typing import Optional


class ContextValidator:
    """
    Validates PII detections using surrounding context.
    Adjusts confidence up or down based on contextual signals.
    """

    # Context keywords that CONFIRM PII
    POSITIVE_CONTEXTS = {
        "EMAIL":    ["email", "mail", "contact", "send", "reply", "from:", "to:", "cc:"],
        "PHONE":    ["phone", "call", "mobile", "tel", "contact", "whatsapp", "number"],
        "AADHAAR":  ["aadhaar", "aadhar", "uid", "uidai", "identity", "biometric"],
        "PAN":      ["pan", "income tax", "tax", "itr", "permanent account"],
        "CREDIT_CARD": ["card", "credit", "debit", "payment", "transaction", "visa", "mastercard"],
        "BANK_ACCOUNT": ["account", "bank", "transfer", "neft", "rtgs", "imps", "savings"],
        "PASSWORD": ["password", "passwd", "pwd", "login", "credentials", "secret"],
        "ADDRESS":  ["address", "street", "road", "lane", "nagar", "colony", "pin", "pincode"],
        "NAME":     ["name", "mr", "mrs", "ms", "dr", "prof", "sir", "madam"],
        "PASSPORT": ["passport", "travel", "visa", "immigration", "nationality"],
    }

    # Context keywords that indicate FALSE POSITIVE
    NEGATIVE_CONTEXTS = {
        "PHONE":    ["version", "v.", "release", "model", "year", "chapter", "page", "item"],
        "AADHAAR":  ["order", "invoice", "ticket", "code", "ref", "receipt"],
        "CREDIT_CARD": ["item", "product", "code", "sku", "ref", "order"],
        "BANK_ACCOUNT": ["zip", "postal", "pin", "code", "id"],
    }

    def validate(self, detection: dict, text: str) -> dict:
        """
        Validate a detection using context.
        Returns the detection with adjusted confidence and validation metadata.
        """
        entity_type = detection["entity_type"]
        start = detection["start"]
        end = detection["end"]

        # Get context window
        ctx_start = max(0, start - 80)
        ctx_end = min(len(text), end + 80)
        context = text[ctx_start:ctx_end].lower()

        confidence = detection["confidence"]
        validation_notes = []

        # Check positive context signals
        pos_signals = self.POSITIVE_CONTEXTS.get(entity_type, [])
        pos_hits = [kw for kw in pos_signals if kw in context]
        if pos_hits:
            confidence = min(1.0, confidence * 1.10)
            validation_notes.append(f"positive_context:{','.join(pos_hits[:2])}")

        # Check negative context signals (false positive indicators)
        neg_signals = self.NEGATIVE_CONTEXTS.get(entity_type, [])
        neg_hits = [kw for kw in neg_signals if kw in context]
        if neg_hits:
            confidence = confidence * 0.65
            validation_notes.append(f"negative_context:{','.join(neg_hits[:2])}")

        # Entity-specific validation
        confidence = self._entity_specific_validation(
            entity_type, detection["value"], context, confidence, validation_notes
        )

        # Filter very low confidence
        is_valid = confidence >= 0.45

        updated = detection.copy()
        updated["confidence"] = round(confidence, 4)
        updated["context_valid"] = is_valid
        updated["context_notes"] = validation_notes
        updated["context_window"] = context[:120]

        return updated

    def _entity_specific_validation(
        self,
        entity_type: str,
        value: str,
        context: str,
        confidence: float,
        notes: list
    ) -> float:

        if entity_type == "NAME":
            # Avoid common false positives (company names, abbreviations)
            if len(value.split()) < 2:
                confidence *= 0.75
                notes.append("single_word_name")
            if value.isupper() and len(value) < 5:
                confidence *= 0.50
                notes.append("likely_abbreviation")

        if entity_type == "BANK_ACCOUNT":
            # Only treat as bank account if financial context is present
            fin_keywords = ["account", "bank", "savings", "current", "neft", "rtgs"]
            if not any(kw in context for kw in fin_keywords):
                confidence *= 0.40
                notes.append("no_financial_context")

        if entity_type == "DATE_OF_BIRTH":
            dob_keywords = ["born", "dob", "birth", "age", "birthday", "date of birth"]
            if any(kw in context for kw in dob_keywords):
                confidence = min(1.0, confidence * 1.15)
                notes.append("dob_context_confirmed")

        if entity_type == "IP_ADDRESS":
            # Check if it's in a technical/log context
            tech_keywords = ["server", "host", "ip", "address", "request", "log", "connect"]
            if any(kw in context for kw in tech_keywords):
                confidence = min(1.0, confidence * 1.10)

        return confidence
