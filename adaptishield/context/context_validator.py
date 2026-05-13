# context/context_validator.py
"""
Context Validator: Analyzes surrounding text to validate PII detections.
Reduces false positives by checking semantic context.

Generic False-Positive Reduction Strategy:
    Instead of writing domain-specific keyword lists (academic, medical, legal...),
    this validator uses two GENERIC signals to distinguish real PII from noise:

    1. STRUCTURED PII CO-OCCURRENCE:
       A person's name is only PII when it co-occurs with structured PII
       (phone, email, Aadhaar, bank account, etc.) in the same document.
       "John von Neumann" in lecture notes = historical reference (no PII nearby).
       "Priya Mehta" next to an Aadhaar number = actual PII.
       This works for ANY content type: storybooks, academic notes, legal docs.

    2. CROSS-DETECTOR AGREEMENT:
       If multiple detectors (regex + transformer + spaCy) agree on an entity,
       it's more likely real PII. If only one detector flags it, apply penalty.
       The transformer model understands language context — if it doesn't see
       a person name where regex does, that's a strong false-positive signal.

Example: "12345 Oak Street" is an ADDRESS, not a bank account number.
Example: "Call +91-9876543210 for support" → phone in support context → valid
"""

import re
from typing import Optional


class ContextValidator:
    """
    Validates PII detections using surrounding context.
    Adjusts confidence up or down based on contextual signals.

    Uses two generic mechanisms to cut false positives:
    - Structured PII co-occurrence (document-level)
    - Cross-detector agreement (per-entity)
    """

    # ── PII Type Categories ────────────────────────────────────────
    # Structured PII: specific formats with built-in validation
    # (digit counts, Luhn checks, format matching) — trust regex alone
    STRUCTURED_PII_TYPES = {
        "AADHAAR", "PAN", "CREDIT_CARD", "EMAIL", "PASSPORT",
        "VOTER_ID", "DRIVING_LICENSE", "GST_NUMBER", "IFSC_CODE",
        "PASSWORD", "UPI_ID", "PHONE", "IP_ADDRESS",
        "BANK_ACCOUNT",
    }

    # Contextual PII: common words/names/dates that appear in regular text
    # — only meaningful as PII when they co-occur with structured PII
    CONTEXTUAL_PII_TYPES = {
        "NAME", "LOCATION", "ORGANIZATION", "DATE_OF_BIRTH",
        "DATE", "URL", "ADDRESS", "AGE", "GENDER",
    }

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
        "BANK_ACCOUNT": ["zip", "postal", "pin", "code", "id",
                         "size", "element", "number of", "n ", "log"],
    }

    def __init__(self):
        # Set by pipeline before validation — enables generic false-positive filtering
        self.structured_pii_found = False  # Are there structured PII entities in this document?
        self.detector_sources_active = set()  # Which detectors found entities? (e.g. {"regex", "transformer"})

    def validate(self, detection: dict, text: str) -> dict:
        """
        Validate a detection using context.
        Returns the detection with adjusted confidence and validation metadata.
        """
        entity_type = detection["entity_type"]
        start = detection["start"]
        end = detection["end"]

        # Get context window (wider = better context understanding)
        ctx_start = max(0, start - 120)
        ctx_end = min(len(text), end + 120)
        context = text[ctx_start:ctx_end].lower()

        confidence = detection["confidence"]
        validation_notes = []

        # ── Step 1: Positive context signals ─────────────────────
        pos_signals = self.POSITIVE_CONTEXTS.get(entity_type, [])
        pos_hits = [kw for kw in pos_signals if kw in context]
        if pos_hits:
            confidence = min(1.0, confidence * 1.10)
            validation_notes.append(f"positive_context:{','.join(pos_hits[:2])}")

        # ── Step 2: Negative context signals ─────────────────────
        neg_signals = self.NEGATIVE_CONTEXTS.get(entity_type, [])
        neg_hits = [kw for kw in neg_signals if kw in context]
        if neg_hits:
            confidence = confidence * 0.65
            validation_notes.append(f"negative_context:{','.join(neg_hits[:2])}")

        # ── Step 3: Entity-specific validation ───────────────────
        confidence = self._entity_specific_validation(
            entity_type, detection["value"], context, confidence, validation_notes
        )

        # ── Step 4: GENERIC — Structured PII co-occurrence check ─
        # This is the core false-positive filter. It works for ANY
        # document type without domain-specific keyword lists.
        #
        # Logic: Contextual PII (names, dates, locations, URLs) is only
        # meaningful when it appears alongside structured PII (phone,
        # email, Aadhaar, etc.) in the same document.
        # In a storybook, lecture notes, or recipe — there's no
        # structured PII, so names/dates are just regular text.
        if entity_type in self.CONTEXTUAL_PII_TYPES:
            if not self.structured_pii_found:
                # No structured PII in document → contextual entities
                # are likely just regular references, not real PII
                confidence *= 0.20
                validation_notes.append("no_structured_pii_cooccurrence")

        # ── Step 5: GENERIC — Cross-detector agreement check ─────
        # If multiple detectors agree on an entity, it's more reliable.
        # Single-detector contextual PII gets a penalty.
        source = detection.get("source", "")
        if entity_type in self.CONTEXTUAL_PII_TYPES:
            n_detectors = source.count("+") + 1 if "+" in source else 1
            if n_detectors == 1 and not pos_hits:
                # Single detector AND no positive context → penalty
                confidence *= 0.70
                validation_notes.append(f"single_detector_no_context")
            elif n_detectors >= 2:
                # Multi-detector agreement → boost
                confidence = min(1.0, confidence * 1.05)
                validation_notes.append(f"multi_detector_agreement")

        # ── Step 6: Final threshold ──────────────────────────────
        if entity_type in self.STRUCTURED_PII_TYPES and "regex" in source:
            is_valid = confidence >= 0.25
        else:
            is_valid = confidence >= 0.30

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
