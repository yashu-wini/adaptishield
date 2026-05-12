# ingestion/pdf_parser.py

from pathlib import Path
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class PDFParser:
    """
    Extracts text from PDF files using PyMuPDF (fitz).
    Falls back to pdfplumber for complex layouts.
    """

    def parse(self, file_path: str) -> dict:
        """
        Parse a PDF and return structured content.
        Returns: { text, pages, metadata }
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"PDF not found: {file_path}")

        try:
            return self._parse_with_pymupdf(file_path)
        except Exception as e:
            logger.warning(f"PyMuPDF failed ({e}), falling back to pdfplumber")
            return self._parse_with_pdfplumber(file_path)

    def _parse_with_pymupdf(self, file_path: str) -> dict:
        import fitz  # PyMuPDF
        doc = fitz.open(file_path)
        pages = []
        full_text = []

        for page_num, page in enumerate(doc):
            page_text = page.get_text("text")
            pages.append({
                "page": page_num + 1,
                "text": page_text,
                "char_count": len(page_text)
            })
            full_text.append(page_text)

        metadata = doc.metadata or {}
        doc.close()

        return {
            "text": "\n".join(full_text),
            "pages": pages,
            "metadata": {
                "title": metadata.get("title", ""),
                "author": metadata.get("author", ""),
                "page_count": len(pages),
                "source": file_path,
                "parser": "pymupdf"
            }
        }

    def _parse_with_pdfplumber(self, file_path: str) -> dict:
        import pdfplumber
        pages = []
        full_text = []

        with pdfplumber.open(file_path) as pdf:
            for i, page in enumerate(pdf.pages):
                page_text = page.extract_text() or ""
                pages.append({
                    "page": i + 1,
                    "text": page_text,
                    "char_count": len(page_text)
                })
                full_text.append(page_text)

        return {
            "text": "\n".join(full_text),
            "pages": pages,
            "metadata": {
                "page_count": len(pages),
                "source": file_path,
                "parser": "pdfplumber"
            }
        }

    def parse_bytes(self, pdf_bytes: bytes) -> dict:
        """Parse PDF from bytes (for API uploads)."""
        import fitz
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        pages = []
        full_text = []
        for page_num, page in enumerate(doc):
            page_text = page.get_text("text")
            pages.append({"page": page_num + 1, "text": page_text})
            full_text.append(page_text)
        doc.close()
        return {
            "text": "\n".join(full_text),
            "pages": pages,
            "metadata": {"page_count": len(pages), "parser": "pymupdf"}
        }
