# ingestion/docx_parser.py

from pathlib import Path
from typing import Optional


class DocxParser:
    """Extracts text and metadata from .docx files using python-docx."""

    def parse(self, file_path: str) -> dict:
        from docx import Document
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"DOCX not found: {file_path}")

        doc = Document(file_path)
        paragraphs = []
        full_text = []

        for para in doc.paragraphs:
            if para.text.strip():
                paragraphs.append({
                    "style": para.style.name,
                    "text": para.text
                })
                full_text.append(para.text)

        # Extract tables
        tables_text = []
        for table in doc.tables:
            for row in table.rows:
                row_text = " | ".join(cell.text for cell in row.cells if cell.text.strip())
                if row_text:
                    tables_text.append(row_text)

        all_text = "\n".join(full_text + tables_text)

        props = doc.core_properties
        return {
            "text": all_text,
            "paragraphs": paragraphs,
            "metadata": {
                "title": props.title or "",
                "author": props.author or "",
                "source": file_path,
                "parser": "python-docx"
            }
        }
