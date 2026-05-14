# context/context_validator.py
"""
Context Validator: Analyzes surrounding text to validate PII detections.
Reduces false positives by checking semantic context.

Generic False-Positive Reduction Strategy:
    This validator uses three GENERIC signals to distinguish real PII from noise:

    1. PRECEDING LABEL ANALYSIS (NEW):
       If a detected value is preceded by a descriptive label like "Tracking:",
       "Order ID:", "Version:", etc., and that label does NOT match a known
       PII-confirming keyword for this entity type, the detection is penalized.
       This works because real PII typically appears after PII-confirming labels
       ("Aadhaar:", "Card:", "Email:") — not generic reference labels.

       Example: "Tracking: 4532015112830366" → "tracking" is NOT in CREDIT_CARD
       positive context → strong penalty → filtered out.
       Example: "Card: 4532015112830366" → "card" IS in CREDIT_CARD positive
       context → no penalty (may even boost).

    2. STRUCTURED PII CO-OCCURRENCE:
       Contextual PII (names, dates) is only meaningful when it co-occurs
       with structured PII in the same document.

    3. CROSS-DETECTOR AGREEMENT:
       Single-detector contextual PII without positive context gets penalized.
"""

import re
from typing import Optional, Tuple


class ContextValidator:
    """
    Validates PII detections using surrounding context.
    Adjusts confidence up or down based on contextual signals.

    Core mechanisms:
    - Preceding label analysis (general-purpose false positive filter)
    - Structured PII co-occurrence (document-level)
    - Cross-detector agreement (per-entity)
    """

    # ── PII Type Categories ────────────────────────────────────────
    STRUCTURED_PII_TYPES = {
        "AADHAAR", "PAN", "CREDIT_CARD", "EMAIL", "PASSPORT",
        "VOTER_ID", "DRIVING_LICENSE", "GST_NUMBER", "IFSC_CODE",
        "PASSWORD", "UPI_ID", "PHONE", "IP_ADDRESS",
        "BANK_ACCOUNT",
    }

    CONTEXTUAL_PII_TYPES = {
        "NAME", "LOCATION", "ORGANIZATION", "DATE_OF_BIRTH",
        "DATE", "URL", "ADDRESS", "AGE", "GENDER",
    }

    # ── Numeric PII types that are vulnerable to label-based false positives ──
    # These are types where the matched value is primarily numeric/alphanumeric
    # and thus ambiguous without context (could be order numbers, tracking IDs,
    # variable names, version numbers, etc.)
    LABEL_SENSITIVE_PII_TYPES = {
        "AADHAAR", "CREDIT_CARD", "PHONE", "BANK_ACCOUNT",
        "PINCODE", "IP_ADDRESS", "PAN",
    }

    # Context keywords that CONFIRM PII
    POSITIVE_CONTEXTS = {
        "EMAIL":    ["email", "mail", "contact", "send", "reply", "from:", "to:", "cc:", "e-mail"],
        "PHONE":    ["phone", "call", "mobile", "tel", "contact", "whatsapp", "cell", "dial"],
        "AADHAAR":  ["aadhaar", "aadhar", "uid", "uidai", "identity", "biometric", "enrolment"],
        "PAN":      ["pan", "income tax", "tax", "itr", "permanent account", "pan card"],
        "CREDIT_CARD": ["card", "credit", "debit", "payment", "visa", "mastercard",
                        "amex", "rupay", "cc", "cvv", "expiry"],
        "BANK_ACCOUNT": ["account", "bank", "transfer", "neft", "rtgs", "imps",
                         "savings", "current account", "a/c", "acct"],
        "PASSWORD": ["password", "passwd", "pwd", "login", "credentials", "secret", "passphrase"],
        "ADDRESS":  ["address", "street", "road", "lane", "nagar", "colony", "pin", "pincode",
                     "residing", "residence"],
        "NAME":     ["name", "mr", "mrs", "ms", "dr", "prof", "sir", "madam",
                     "applicant", "holder", "customer", "beneficiary"],
        "PASSPORT": ["passport", "travel", "visa", "immigration", "nationality"],
        "PINCODE":  ["pin", "pincode", "postal", "zip", "area code", "pin code"],
        "IP_ADDRESS": ["ip", "server", "host", "address", "client", "remote", "proxy"],
        "VOTER_ID": ["voter", "election", "electoral", "voter id"],
        "DRIVING_LICENSE": ["license", "licence", "driving", "dl", "rto"],
        "GST_NUMBER": ["gst", "gstin", "tax", "goods and services"],
        "IFSC_CODE": ["ifsc", "bank", "branch", "neft", "rtgs"],
        "UPI_ID": ["upi", "payment", "pay", "gpay", "phonepe", "paytm"],
    }

    # Context keywords that indicate FALSE POSITIVE
    NEGATIVE_CONTEXTS = {
        "PHONE":    ["version", "v.", "release", "model", "year", "chapter", "page",
                     "item", "build", "revision"],
        "AADHAAR":  ["order", "invoice", "ticket", "code", "ref", "receipt",
                     "serial", "batch", "lot"],
        "CREDIT_CARD": ["item", "product", "code", "sku", "ref", "order",
                        "tracking", "serial", "batch", "invoice"],
        "BANK_ACCOUNT": ["zip", "postal", "pin", "code", "id",
                         "size", "element", "number of", "n ", "log"],
        "PINCODE":  ["version", "build", "release", "population", "count",
                     "total", "score", "code", "id"],
    }

    # Words that follow a number and indicate it's a count/metric, NOT PII
    QUANTITY_INDICATORS = {
        # Social media / engagement
        "followers", "subscribers", "users", "views", "likes",
        "downloads", "impressions", "clicks", "shares", "posts",
        "comments", "reviews", "stars", "ratings",
        # General counts
        "items", "records", "entries", "rows", "transactions",
        "people", "members", "customers", "students", "employees",
        "patients", "votes", "points", "results", "matches",
        # Units / measurements
        "times", "attempts", "steps", "miles", "meters", "km",
        "kg", "lbs", "dollars", "rupees", "percent", "units",
        # Time
        "years", "months", "days", "hours", "minutes", "seconds",
        # Documents
        "pages", "chapters", "lines", "words", "characters",
    }

    def __init__(self):
        # Set by pipeline before validation — enables generic false-positive filtering
        self.structured_pii_found = False
        self.detector_sources_active = set()

    def validate(self, detection: dict, text: str) -> dict:
        """
        Validate a detection using context.
        Returns the detection with adjusted confidence and validation metadata.
        """
        entity_type = detection["entity_type"]
        start = detection["start"]
        end = detection["end"]

        # Get context window
        ctx_start = max(0, start - 120)
        ctx_end = min(len(text), end + 120)
        context = text[ctx_start:ctx_end].lower()

        confidence = detection["confidence"]
        validation_notes = []

        # ── Step 1: Preceding label analysis (GENERAL-PURPOSE) ────
        # This is the key false-positive filter. If the entity appears
        # after a label like "Tracking:", "Order:", "Reference:", and
        # that label is NOT a PII-confirming keyword, the detection is
        # penalized heavily. This works for ALL entity types without
        # hardcoding specific label lists.
        label_result, label_text = self._detect_preceding_label(
            detection, text
        )
        if label_result == "confirming":
            confidence = min(1.0, confidence * 1.15)
            validation_notes.append(f"confirming_label:{label_text}")
        elif label_result == "competing":
            # Strong penalty — the label suggests a non-PII interpretation
            confidence *= 0.20
            validation_notes.append(f"competing_label:{label_text}")

        # ── Step 2: Positive context signals ─────────────────────
        pos_signals = self.POSITIVE_CONTEXTS.get(entity_type, [])
        pos_hits = [kw for kw in pos_signals if kw in context]
        if pos_hits and label_result != "confirming":
            # Only apply if label didn't already boost
            confidence = min(1.0, confidence * 1.10)
            validation_notes.append(f"positive_context:{','.join(pos_hits[:2])}")

        # ── Step 3: Negative context signals ─────────────────────
        neg_signals = self.NEGATIVE_CONTEXTS.get(entity_type, [])
        neg_hits = [kw for kw in neg_signals if kw in context]
        if neg_hits and label_result != "competing":
            # Only apply if label didn't already penalize
            confidence = confidence * 0.65
            validation_notes.append(f"negative_context:{','.join(neg_hits[:2])}")

        # ── Step 3.5: Following-word analysis ────────────────────
        # If the word immediately after a numeric entity is a quantity
        # indicator ("followers", "items", "users"), the number is
        # likely a count/metric, not PII. This catches cases like
        # "I have reached 7000138006 followers" without needing
        # a transformer.
        if entity_type in self.LABEL_SENSITIVE_PII_TYPES:
            post_text = text[end:min(len(text), end + 40)].strip().lower()
            words_after = post_text.split()
            if words_after:
                first_word_after = words_after[0].rstrip('.,;:!?')
                if first_word_after in self.QUANTITY_INDICATORS:
                    confidence *= 0.15
                    validation_notes.append(f"quantity_follows:{first_word_after}")

        # ── Step 4: Entity-specific validation ───────────────────
        confidence = self._entity_specific_validation(
            entity_type, detection["value"], context, confidence,
            validation_notes, detection, text
        )

        # ── Step 5: GENERIC — Structured PII co-occurrence check ─
        if entity_type in self.CONTEXTUAL_PII_TYPES:
            if not self.structured_pii_found:
                confidence *= 0.20
                validation_notes.append("no_structured_pii_cooccurrence")

        # ── Step 6: GENERIC — Cross-detector agreement check ─────
        source = detection.get("source", "")
        if entity_type in self.CONTEXTUAL_PII_TYPES:
            n_detectors = source.count("+") + 1 if "+" in source else 1
            if n_detectors == 1 and not pos_hits:
                confidence *= 0.70
                validation_notes.append(f"single_detector_no_context")
            elif n_detectors >= 2:
                confidence = min(1.0, confidence * 1.05)
                validation_notes.append(f"multi_detector_agreement")

        # ── Step 7: Final threshold ──────────────────────────────
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

    def _detect_preceding_label(
        self, detection: dict, text: str
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        General-purpose preceding label detector.

        Checks if the detected entity value is preceded by a descriptive
        label (e.g., "Tracking:", "Order ID =", "Card number:").

        Returns:
            (label_type, label_text) where label_type is:
            - "confirming": label matches a positive context keyword → boost
            - "competing": label does NOT match positive context → penalty
            - None: no label pattern found
        """
        entity_type = detection["entity_type"]
        start = detection["start"]

        # Extract text before the entity (up to 50 chars)
        prefix_start = max(0, start - 50)
        prefix = text[prefix_start:start]

        if not prefix.strip():
            return None, None

        # Look for LABEL followed by separator (: = – —)
        # The label must start with a letter (not digits like "+91")
        # and be at least 2 alphabetic chars to be meaningful.
        # Note: we do NOT include bare hyphen (-) as separator because
        # it conflicts with phone number prefixes like "+91-".
        label_match = re.search(
            r'([a-zA-Z][\w\s]{0,25}?)\s*[:=–—]\s*$',
            prefix
        )

        if not label_match:
            return None, None

        label = label_match.group(1).strip().lower()

        # Label must be at least 2 chars and contain letters
        if not label or len(label) < 2 or not any(c.isalpha() for c in label):
            return None, None

        # Check if label contains any positive context keyword for this entity
        positive_keywords = self.POSITIVE_CONTEXTS.get(entity_type, [])
        for kw in positive_keywords:
            if kw in label:
                return "confirming", label

        # The label doesn't match any known PII-confirming keyword.
        # For numeric PII types, this is a strong signal of false positive
        # because numeric values are inherently ambiguous.
        # For highly-formatted types (EMAIL, URL), the format itself
        # is strong enough evidence — a label matters less.
        if entity_type in self.LABEL_SENSITIVE_PII_TYPES:
            return "competing", label

        # For format-specific types (EMAIL, UPI_ID, etc.), the format
        # is strong enough evidence. Only penalize if the label
        # explicitly suggests a different interpretation.
        return None, None

    def _entity_specific_validation(
        self,
        entity_type: str,
        value: str,
        context: str,
        confidence: float,
        notes: list,
        detection: dict = None,
        text: str = None,
    ) -> float:

        if entity_type == "NAME":
            if len(value.split()) < 2:
                confidence *= 0.75
                notes.append("single_word_name")
            if value.isupper() and len(value) < 5:
                confidence *= 0.50
                notes.append("likely_abbreviation")

        if entity_type == "PAN":
            # PAN format [A-Z]{5}[0-9]{4}[A-Z] is very common in regular
            # text (variable names, algorithm names, abbreviations).
            # Require PII-confirming context to treat it as real PAN.
            pan_keywords = ["pan", "income tax", "tax", "itr", "permanent account",
                            "pan card", "pan no", "taxation"]
            if not any(kw in context for kw in pan_keywords):
                confidence *= 0.25
                notes.append("no_pan_context")

        if entity_type == "PHONE" and detection and text:
            # Check if the phone number is directly preceded by a decimal
            # point + digit, indicating a version/decimal number.
            # E.g., "Python 3.9876543210" → not a phone number.
            start = detection["start"]
            if start >= 2:
                preceding = text[max(0, start - 5):start]
                if re.search(r'\d\.\s*$', preceding):
                    confidence *= 0.15
                    notes.append("version_decimal_prefix")

        if entity_type == "BANK_ACCOUNT":
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
            tech_keywords = ["server", "host", "ip", "address", "request", "log", "connect"]
            if any(kw in context for kw in tech_keywords):
                confidence = min(1.0, confidence * 1.10)

        if entity_type == "PASSWORD":
            # Validate the captured value looks like an actual credential,
            # not a discussion about passwords (e.g., "password policy")
            pwd_match = re.match(
                r'(?i)(?:password|passwd|pwd)[\s:=]+(\S+)', value
            )
            if pwd_match:
                pwd_value = pwd_match.group(1)
                # Strip trailing punctuation — "policy:" → "policy"
                # Colons, semicolons, commas etc. are sentence punctuation,
                # not indicators of password complexity.
                pwd_value = pwd_value.rstrip(':;,.!?')
                has_digit = bool(re.search(r'\d', pwd_value))
                has_special = bool(re.search(r'[^a-zA-Z0-9]', pwd_value))
                is_long_enough = len(pwd_value) >= 6
                # Real passwords have digits/specials; plain English words don't
                if not has_digit and not has_special:
                    confidence *= 0.25
                    notes.append("password_looks_like_plain_word")
                elif not is_long_enough:
                    confidence *= 0.50
                    notes.append("password_too_short")

        if entity_type == "PINCODE":
            # Pincodes are just 6-digit numbers — extremely ambiguous.
            # Only trust them near address/location context.
            pin_keywords = ["pin", "pincode", "postal", "zip", "address",
                            "city", "state", "district", "area", "locality",
                            "nagar", "colony", "street", "road"]
            if not any(kw in context for kw in pin_keywords):
                confidence *= 0.30
                notes.append("no_address_context_for_pincode")

        return confidence
