# ingestion/text_cleaner.py

import re
import unicodedata
from typing import Optional


class TextCleaner:
    """
    Cleans and normalizes raw text before PII detection.
    Handles encoding issues, whitespace normalization, and noise removal.
    """

    def clean(self, text: str, preserve_structure: bool = True) -> str:
        if not text:
            return ""

        # Normalize unicode
        text = unicodedata.normalize("NFKC", text)

        # Fix common OCR artifacts
        text = self._fix_ocr_artifacts(text)

        # Normalize whitespace (but preserve newlines for structure)
        if preserve_structure:
            text = re.sub(r"[^\S\n]+", " ", text)
            text = re.sub(r"\n{3,}", "\n\n", text)
        else:
            text = re.sub(r"\s+", " ", text)

        # Remove null bytes and control characters (except newlines/tabs)
        text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)

        return text.strip()

    def _fix_ocr_artifacts(self, text: str) -> str:
        # Fix common OCR number/letter confusions in structured data
        # e.g. "Aadhaar: 1234 5678 9Ol2" → "1234 5678 9012"
        text = re.sub(r"(?<=\d)[Ol](?=\d)", "0", text)
        text = re.sub(r"(?<=\d)I(?=\d)", "1", text)
        return text

    def split_into_sentences(self, text: str) -> list[str]:
        """Split text into sentences for context analysis."""
        sentences = re.split(r"(?<=[.!?])\s+", text)
        return [s.strip() for s in sentences if s.strip()]

    def extract_context_window(self, text: str, position: int, window: int = 50) -> str:
        """Get surrounding context around a detected PII position."""
        start = max(0, position - window)
        end = min(len(text), position + window)
        return text[start:end]
