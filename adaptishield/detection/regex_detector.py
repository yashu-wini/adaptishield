# detection/regex_detector.py

import re
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from configs.pii_config import GENERIC_PII_PATTERNS, INDIAN_PII_PATTERNS


class RegexDetector:
    """
    Fast regex-based PII detector.
    Detects structured PII: emails, phones, Aadhaar, PAN, credit cards, etc.
    Returns high-confidence detections for structured patterns.
    """

    def __init__(self):
        # Compile all patterns once
        self.patterns = {}
        for name, pattern in {**GENERIC_PII_PATTERNS, **INDIAN_PII_PATTERNS}.items():
            try:
                self.patterns[name] = re.compile(pattern)
            except re.error as e:
                print(f"[RegexDetector] Warning: Bad pattern for {name}: {e}")

    def detect(self, text: str) -> list[dict]:
        """
        Detect PII using regex patterns.
        Returns list of detection dicts with entity_type, value, start, end, confidence.
        """
        detections = []
        seen_spans = set()

        for entity_type, pattern in self.patterns.items():
            for match in pattern.finditer(text):
                start, end = match.start(), match.end()

                # Skip overlapping spans
                span = (start, end)
                if any(s <= start < e or s < end <= e for s, e in seen_spans):
                    continue

                value = match.group()

                # Validate and assign confidence
                confidence = self._validate(entity_type, value)
                if confidence is None:
                    continue

                detections.append({
                    "entity_type": entity_type,
                    "value": value,
                    "start": start,
                    "end": end,
                    "confidence": confidence,
                    "source": "regex"
                })
                seen_spans.add(span)

        return detections

    def _validate(self, entity_type: str, value: str) -> float | None:
        """Extra validation per entity type. Returns confidence or None to skip."""
        if entity_type == "AADHAAR":
            digits = re.sub(r"\s", "", value)
            if len(digits) != 12:
                return None
            # Reject if all digits are the same (e.g., 111111111111)
            if len(set(digits)) <= 2:
                return None
            return 0.90

        if entity_type == "PAN":
            if not re.fullmatch(r"[A-Z]{5}[0-9]{4}[A-Z]", value):
                return None
            return 0.95

        if entity_type == "EMAIL":
            return 0.92

        if entity_type == "PHONE":
            digits = re.sub(r"\D", "", value)
            if len(digits) < 10:
                return None
            return 0.88

        if entity_type == "CREDIT_CARD":
            digits = re.sub(r"\D", "", value)
            if not self._luhn_check(digits):
                return None
            # Credit card passes Luhn, but Luhn is not unique to credit cards.
            # Use moderate confidence — context validator will boost or penalize.
            return 0.80

        if entity_type == "PASSWORD":
            # Extract the value part after the keyword (password: XXXXX)
            pwd_match = re.match(r'(?i)(?:password|passwd|pwd)[\s:=]+(\S+)', value)
            if pwd_match:
                pwd_value = pwd_match.group(1)
                # Strip trailing sentence punctuation — "policy:" → "policy"
                # These are part of the sentence, not the password itself.
                pwd_value = pwd_value.rstrip(':;,.!?')
                if not pwd_value:
                    return None
                has_digit = bool(re.search(r'\d', pwd_value))
                has_special = bool(re.search(r'[^a-zA-Z0-9]', pwd_value))
                # High confidence only if the value looks like a real credential
                if has_digit or has_special:
                    return 0.95
                # Plain word after "password:" — lower confidence, let context decide
                return 0.55
            return 0.55

        if entity_type == "IP_ADDRESS":
            parts = value.split(".")
            try:
                int_parts = [int(p) for p in parts]
            except ValueError:
                return None
            if not all(0 <= p <= 255 for p in int_parts):
                return None
            # Filter non-PII addresses: 0.0.0.0, 255.255.255.255, broadcast
            if value in ("0.0.0.0", "255.255.255.255"):
                return None
            # Subnet masks (all octets are 255 or 0, e.g. 255.255.255.0)
            if all(p in (0, 255) for p in int_parts):
                return None
            if value.startswith(("192.168.", "10.", "127.", "172.")):
                return 0.60  # Private IP, lower sensitivity
            return 0.75

        if entity_type == "PINCODE":
            # Pincodes are extremely ambiguous (any 6-digit number).
            # Assign lower confidence — context validator will boost if
            # address-related keywords are nearby.
            return 0.50

        return 0.85  # Default

    def _luhn_check(self, digits: str) -> bool:
        """Validate credit card number using Luhn algorithm."""
        try:
            total = 0
            for i, d in enumerate(reversed(digits)):
                n = int(d)
                if i % 2 == 1:
                    n *= 2
                    if n > 9:
                        n -= 9
                total += n
            return total % 10 == 0
        except Exception:
            return False
