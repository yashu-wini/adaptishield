# anonymization/masking.py
"""
Adaptive Anonymization Engine
Applies different anonymization strategies based on sensitivity level:
  LOW:      MASK     → r***@gmail.com
  MEDIUM:   TOKENIZE → PHONE_TOKEN_3f8a
  HIGH:     REDACT   → [REDACTED]
  CRITICAL: REDACT   → [REDACTED]
"""

import re
import uuid
import hashlib
from typing import Optional


class MaskingEngine:
    def mask(self, value: str, entity_type: str) -> str:
        """Mask PII, preserving some structure."""
        if entity_type == "EMAIL":
            return self._mask_email(value)
        if entity_type == "PHONE":
            return self._mask_phone(value)
        if entity_type == "NAME":
            return self._mask_name(value)
        if entity_type == "IP_ADDRESS":
            return self._mask_ip(value)
        # Generic masking: keep first and last char
        if len(value) <= 2:
            return "*" * len(value)
        return value[0] + "*" * (len(value) - 2) + value[-1]

    def _mask_email(self, email: str) -> str:
        if "@" not in email:
            return "***@***.***"
        local, domain = email.split("@", 1)
        masked_local = local[0] + "***" if local else "***"
        return f"{masked_local}@{domain}"

    def _mask_phone(self, phone: str) -> str:
        digits = re.sub(r"\D", "", phone)
        if len(digits) >= 10:
            return digits[:2] + "****" + digits[-4:]
        return "****" + digits[-3:] if len(digits) >= 3 else "****"

    def _mask_name(self, name: str) -> str:
        parts = name.split()
        masked = []
        for part in parts:
            if len(part) <= 1:
                masked.append(part)
            else:
                masked.append(part[0] + "." * (len(part) - 1))
        return " ".join(masked)

    def _mask_ip(self, ip: str) -> str:
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.***. ***"
        return "***.***.***. ***"


class TokenizationEngine:
    def __init__(self):
        self._token_map: dict[str, str] = {}
        self._reverse_map: dict[str, str] = {}

    def tokenize(self, value: str, entity_type: str) -> str:
        """Replace PII with a deterministic, reversible token."""
        if value in self._token_map:
            return self._token_map[value]

        # Generate short hash-based token
        short_hash = hashlib.sha256(value.encode()).hexdigest()[:8].upper()
        token = f"{entity_type}_TOKEN_{short_hash}"

        self._token_map[value] = token
        self._reverse_map[token] = value
        return token

    def detokenize(self, token: str) -> Optional[str]:
        """Reverse a token back to its original value (authorized access only)."""
        return self._reverse_map.get(token)

    def get_token_map(self) -> dict:
        """Export token mapping (for secure storage)."""
        return dict(self._token_map)


class RedactionEngine:
    def redact(self, value: str, entity_type: str) -> str:
        """Full redaction — replaces with [REDACTED] label."""
        return f"[{entity_type}_REDACTED]"


class AdaptiveAnonymizer:
    """
    Main anonymization interface.
    Chooses strategy based on sensitivity_level.
    """

    def __init__(self):
        self.masker = MaskingEngine()
        self.tokenizer = TokenizationEngine()
        self.redactor = RedactionEngine()

    def anonymize(self, detection: dict) -> dict:
        """
        Apply the appropriate anonymization strategy to a classified detection.
        Expects detection to have 'sensitivity_level' and 'anonymization_strategy'.
        """
        strategy = detection.get("anonymization_strategy", "MASK")
        value = detection["value"]
        entity_type = detection["entity_type"]

        if strategy == "MASK":
            anonymized_value = self.masker.mask(value, entity_type)
        elif strategy == "TOKENIZE":
            anonymized_value = self.tokenizer.tokenize(value, entity_type)
        elif strategy == "REDACT":
            anonymized_value = self.redactor.redact(value, entity_type)
        else:
            anonymized_value = self.masker.mask(value, entity_type)

        updated = detection.copy()
        updated["anonymized_value"] = anonymized_value
        updated["strategy_applied"] = strategy
        return updated

    def apply_to_text(self, text: str, detections: list[dict]) -> str:
        """
        Apply all anonymizations to the full text.
        Processes detections in reverse order (by position) to preserve offsets.
        """
        # Sort detections by start position descending
        sorted_dets = sorted(detections, key=lambda x: x["start"], reverse=True)

        anonymized_text = text
        for det in sorted_dets:
            if "anonymized_value" not in det:
                det = self.anonymize(det)
            start = det["start"]
            end = det["end"]
            anonymized_text = (
                anonymized_text[:start] +
                det["anonymized_value"] +
                anonymized_text[end:]
            )

        return anonymized_text

    def get_token_map(self) -> dict:
        return self.tokenizer.get_token_map()
