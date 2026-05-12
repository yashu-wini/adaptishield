# database/logger.py
"""
Audit Logger: Writes pipeline results to PostgreSQL.
Falls back to JSON file logging if DB is unavailable.
"""

import json
import os
import uuid
from datetime import datetime
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class AuditLogger:
    """
    Logs every pipeline execution to PostgreSQL.
    Falls back to JSON file logs if DB is unavailable.
    """

    def __init__(self, db_session=None, log_dir: str = "logs"):
        self.db_session = db_session
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)

    def log(self, pipeline_result: dict) -> str:
        """
        Log a pipeline result. Returns a document_id.
        """
        doc_id = pipeline_result.get("document_id") or str(uuid.uuid4())[:8]

        if self.db_session:
            self._log_to_db(doc_id, pipeline_result)
        else:
            self._log_to_file(doc_id, pipeline_result)

        return doc_id

    def _log_to_db(self, doc_id: str, result: dict):
        try:
            from database.models import AuditLog
            risk_info = result.get("risk_analysis", {})
            log_entry = AuditLog(
                document_id=doc_id,
                document_name=result.get("document_name", "unknown"),
                document_type=result.get("document_type", "txt"),
                entity_count=risk_info.get("entity_count", 0),
                entity_breakdown=risk_info.get("entity_breakdown", {}),
                risk_score=risk_info.get("risk_score", 0),
                risk_level=risk_info.get("risk_level", "LOW"),
                anonymization_applied=result.get("anonymization_applied", False),
                encrypted=result.get("encrypted", False),
                processing_time_ms=result.get("processing_time_ms", 0),
                full_report=result
            )
            self.db_session.add(log_entry)
            self.db_session.commit()
        except Exception as e:
            logger.error(f"[AuditLogger] DB write failed: {e}")
            self._log_to_file(doc_id, result)

    def _log_to_file(self, doc_id: str, result: dict):
        timestamp = datetime.utcnow().strftime("%Y%m%d")
        log_file = self.log_dir / f"audit_{timestamp}.jsonl"
        entry = {
            "document_id": doc_id,
            "timestamp": datetime.utcnow().isoformat(),
            **result
        }
        with open(log_file, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")

    def get_recent_logs(self, limit: int = 50) -> list[dict]:
        """Read recent logs from file (fallback mode)."""
        logs = []
        log_files = sorted(self.log_dir.glob("audit_*.jsonl"), reverse=True)
        for lf in log_files[:3]:
            try:
                with open(lf) as f:
                    for line in f:
                        logs.append(json.loads(line))
                if len(logs) >= limit:
                    break
            except Exception:
                pass
        return logs[:limit]
