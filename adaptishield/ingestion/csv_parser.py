# ingestion/csv_parser.py

import io
import pandas as pd
from pathlib import Path


class CSVParser:
    """Parses CSV/Excel files and converts to flat text for PII detection."""

    def parse_bytes(self, content: bytes, filename: str = "upload.csv") -> dict:
        """Parse CSV/XLSX from raw bytes (for API uploads)."""
        suffix = Path(filename).suffix.lower()
        buf = io.BytesIO(content)
        if suffix == ".csv":
            df = pd.read_csv(buf, dtype=str, keep_default_na=False)
        elif suffix in [".xlsx", ".xls"]:
            df = pd.read_excel(buf, dtype=str, keep_default_na=False)
        else:
            raise ValueError(f"Unsupported format: {suffix}")
        return self._extract(df, source=filename)

    def parse(self, file_path: str) -> dict:
        path = Path(file_path)
        suffix = path.suffix.lower()

        if suffix == ".csv":
            df = pd.read_csv(file_path, dtype=str, keep_default_na=False)
        elif suffix in [".xlsx", ".xls"]:
            df = pd.read_excel(file_path, dtype=str, keep_default_na=False)
        else:
            raise ValueError(f"Unsupported format: {suffix}")

        return self._extract(df, source=file_path)

    def _extract(self, df, source: str = "unknown") -> dict:
        """Shared extraction logic for both file-path and bytes-based parsing."""
        # Convert each row to text for detection
        rows_text = []
        for _, row in df.iterrows():
            row_text = " | ".join(f"{col}: {val}" for col, val in row.items() if val.strip())
            rows_text.append(row_text)

        return {
            "text": "\n".join(rows_text),
            "rows": df.to_dict(orient="records"),
            "columns": list(df.columns),
            "metadata": {
                "row_count": len(df),
                "col_count": len(df.columns),
                "source": source,
                "parser": "pandas"
            }
        }

