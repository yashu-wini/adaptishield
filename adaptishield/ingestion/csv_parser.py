# ingestion/csv_parser.py

import pandas as pd
from pathlib import Path


class CSVParser:
    """Parses CSV/Excel files and converts to flat text for PII detection."""

    def parse(self, file_path: str) -> dict:
        path = Path(file_path)
        suffix = path.suffix.lower()

        if suffix == ".csv":
            df = pd.read_csv(file_path, dtype=str, keep_default_na=False)
        elif suffix in [".xlsx", ".xls"]:
            df = pd.read_excel(file_path, dtype=str, keep_default_na=False)
        else:
            raise ValueError(f"Unsupported format: {suffix}")

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
                "source": file_path,
                "parser": "pandas"
            }
        }
