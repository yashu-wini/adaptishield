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
            return 0.95

        if entity_type == "PASSWORD":
            return 0.98

        if entity_type == "IP_ADDRESS":
            parts = value.split(".")
            if not all(0 <= int(p) <= 255 for p in parts):
                return None
            if value.startswith(("192.168.", "10.", "127.", "172.")):
                return 0.60  # Private IP, lower sensitivity
            return 0.75

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
