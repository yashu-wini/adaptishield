# pipeline.py
"""
AdaptiShield Pipeline Orchestrator
===================================
Full pipeline: Ingestion → Detection → Context → Sensitivity → Anonymization → Encryption

Usage:
    from pipeline import AdaptiShieldPipeline
    pipeline = AdaptiShieldPipeline()
    result = pipeline.process_text("Hello, my name is Ravi and my Aadhaar is 2345 6789 0123")
"""

import time
import uuid
import logging
from pathlib import Path

# Ingestion
from ingestion.text_cleaner import TextCleaner
from ingestion.pdf_parser import PDFParser
from ingestion.docx_parser import DocxParser
from ingestion.csv_parser import CSVParser

# Detection
from detection.regex_detector import RegexDetector
from detection.transformer_detector import TransformerDetector
from detection.spacy_detector import SpacyDetector
from detection.fusion_engine import FusionEngine

# Context
from context.context_validator import ContextValidator
from context.confidence_engine import ConfidenceEngine
from context.domain_classifier import FinancialDomainClassifier
from context.quasi_identifier_engine import QuasiIdentifierEngine

# Sensitivity
from sensitivity.sensitivity_classifier import SensitivityClassifier

# Anonymization
from anonymization.masking import AdaptiveAnonymizer

# Security
from security.aes_encryptor import AESEncryptor

# Audit
from database.logger import AuditLogger

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(name)s | %(message)s")


class AdaptiShieldPipeline:
    """
    Main pipeline orchestrator for AdaptiShield.
    Runs the full privacy intelligence pipeline on any input text or document.
    """

    def __init__(
        self,
        use_transformer: bool = True,
        use_spacy: bool = True,
        encrypt_output: bool = True,
        log_results: bool = True,
    ):
        logger.info("🛡️  Initializing AdaptiShield Pipeline...")

        # Stage 1: Ingestion
        self.cleaner = TextCleaner()
        self.pdf_parser = PDFParser()
        self.docx_parser = DocxParser()
        self.csv_parser = CSVParser()

        # Stage 2: Detection
        self.regex_detector = RegexDetector()
        self.transformer_detector = TransformerDetector() if use_transformer else None
        self.spacy_detector = SpacyDetector() if use_spacy else None
        self.fusion_engine = FusionEngine()

        # Stage 3: Context
        self.context_validator = ContextValidator()
        self.confidence_engine = ConfidenceEngine()

        # Domain Intelligence (CHANGE 1 — Financial Domain Classification)
        self.domain_classifier = FinancialDomainClassifier()

        # Quasi-Identifier Analysis (CHANGE 2 — Re-identification Risk)
        self.quasi_id_engine = QuasiIdentifierEngine()

        # Stage 4: Sensitivity
        self.sensitivity_classifier = SensitivityClassifier()

        # Stage 5: Anonymization
        self.anonymizer = AdaptiveAnonymizer()

        # Stage 6: Encryption
        self.encryptor = AESEncryptor() if encrypt_output else None
        self.encrypt_output = encrypt_output

        # Logging
        self.audit_logger = AuditLogger() if log_results else None

        logger.info("✅ Pipeline initialized successfully.")

    # ─────────────────────────────────────────────
    # Public Interface
    # ─────────────────────────────────────────────

    def process_text(self, text: str, document_name: str = "inline_text") -> dict:
        """Process raw text through the full pipeline."""
        return self._run_pipeline(text, document_name=document_name, document_type="txt")

    def process_file(self, file_path: str) -> dict:
        """Ingest and process a file (PDF, DOCX, CSV, TXT)."""
        path = Path(file_path)
        suffix = path.suffix.lower()

        if suffix == ".pdf":
            parsed = self.pdf_parser.parse(file_path)
        elif suffix == ".docx":
            parsed = self.docx_parser.parse(file_path)
        elif suffix in [".csv", ".xlsx"]:
            parsed = self.csv_parser.parse(file_path)
        elif suffix == ".txt":
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                parsed = {"text": f.read(), "metadata": {}}
        else:
            raise ValueError(f"Unsupported file type: {suffix}")

        return self._run_pipeline(
            parsed["text"],
            document_name=path.name,
            document_type=suffix.lstrip("."),
            metadata=parsed.get("metadata", {})
        )

    def process_bytes(self, content: bytes, filename: str = "upload.pdf") -> dict:
        """Process file bytes (for API uploads)."""
        suffix = Path(filename).suffix.lower()
        metadata = {}

        if suffix == ".pdf":
            parsed = self.pdf_parser.parse_bytes(content)
            text = parsed["text"]
            metadata = parsed.get("metadata", {})
        elif suffix == ".docx":
            parsed = self.docx_parser.parse_bytes(content)
            text = parsed["text"]
            metadata = parsed.get("metadata", {})
        elif suffix in [".csv", ".xlsx", ".xls"]:
            parsed = self.csv_parser.parse_bytes(content, filename=filename)
            text = parsed["text"]
            metadata = parsed.get("metadata", {})
        elif suffix == ".txt":
            text = content.decode("utf-8", errors="replace")
        else:
            raise ValueError(f"Unsupported file type: {suffix}")

        return self._run_pipeline(text, document_name=filename, document_type=suffix.lstrip("."), metadata=metadata)

    # ─────────────────────────────────────────────
    # Core Pipeline
    # ─────────────────────────────────────────────

    def _run_pipeline(
        self,
        raw_text: str,
        document_name: str = "unknown",
        document_type: str = "txt",
        metadata: dict = None
    ) -> dict:
        start_time = time.time()
        doc_id = str(uuid.uuid4())[:12]

        logger.info(f"📄 Processing document: {document_name} [{doc_id}]")

        # ── Stage 1: Clean ──────────────────────────────
        text = self.cleaner.clean(raw_text)
        logger.info(f"  ✅ Stage 1: Text cleaned ({len(text)} chars)")

        # ── Stage 1.5: Domain Classification (CHANGE 1) ──
        domain_info = self.domain_classifier.classify(text)
        domain_multiplier = self.domain_classifier.get_domain_risk_multiplier(
            domain_info["domain"]
        )
        logger.info(
            f"  ✅ Stage 1.5: Domain = {domain_info['domain']} "
            f"(financial={domain_info['is_financial']}, "
            f"confidence={domain_info['domain_confidence']}, "
            f"multiplier={domain_multiplier})"
        )

        # ── Stage 2: Detect ─────────────────────────────
        regex_dets = self.regex_detector.detect(text)
        transformer_dets = self.transformer_detector.detect(text) if self.transformer_detector else []
        spacy_dets = self.spacy_detector.detect(text) if self.spacy_detector else []

        fused = self.fusion_engine.fuse(regex_dets, transformer_dets, spacy_dets)
        logger.info(
            f"  ✅ Stage 2: Detection — "
            f"regex={len(regex_dets)}, transformer={len(transformer_dets)}, "
            f"spacy={len(spacy_dets)}, fused={len(fused)}"
        )

        # ── Stage 3: Context Validation ─────────────────
        # GENERIC false-positive filtering: Check if the document
        # contains any structured PII (phone, email, Aadhaar, etc.).
        # If it does, contextual entities (names, dates, URLs) are
        # likely real PII. If not, they're just regular text references.
        # This works for ANY content type without domain-specific rules.
        STRUCTURED_PII_TYPES = {
            "EMAIL", "PHONE", "AADHAAR", "PAN", "CREDIT_CARD", "PASSPORT",
            "BANK_ACCOUNT", "PASSWORD", "VOTER_ID", "DRIVING_LICENSE",
            "GST_NUMBER", "IFSC_CODE", "UPI_ID", "IP_ADDRESS",
        }
        has_structured_pii = any(
            d["entity_type"] in STRUCTURED_PII_TYPES for d in fused
        )
        active_sources = set()
        for d in fused:
            for s in d.get("source", "").split("+"):
                active_sources.add(s)

        self.context_validator.structured_pii_found = has_structured_pii
        self.context_validator.detector_sources_active = active_sources

        all_validated = [self.context_validator.validate(d, text) for d in fused]
        validated = [d for d in all_validated if d.get("context_valid", True)]
        rejected = [d for d in all_validated if not d.get("context_valid", True)]
        if rejected:
            for r in rejected:
                logger.info(
                    f"    ⚠ Context rejected: {r['entity_type']}='{r['value']}' "
                    f"conf={r['confidence']:.4f} notes={r.get('context_notes', [])}"
                )
        recalibrated = self.confidence_engine.recalibrate(validated)
        logger.info(
            f"  ✅ Stage 3: Context — {len(recalibrated)} entities after validation "
            f"(rejected {len(rejected)}, structured_pii={has_structured_pii})"
        )

        # ── Stage 4: Sensitivity ─────────────────────────
        risk_analysis = self.sensitivity_classifier.classify_document(recalibrated)
        classified_entities = risk_analysis.pop("classified_entities", recalibrated)
        logger.info(
            f"  ✅ Stage 4: Risk = {risk_analysis['risk_score']} ({risk_analysis['risk_level']})"
        )

        # ── Stage 4.5: Quasi-Identifier Correlation (CHANGE 2) ──
        quasi_id_analysis = self.quasi_id_engine.analyze(classified_entities)
        # Apply domain multiplier and correlation risk to the overall risk score
        base_risk = risk_analysis["risk_score"]
        correlation_risk = quasi_id_analysis["total_correlation_score"]
        adjusted_risk = (base_risk * domain_multiplier) + correlation_risk
        # Re-classify risk level with adjusted score
        from configs.pii_config import RISK_LEVELS
        adjusted_level = "LOW"
        for level, (low, high) in RISK_LEVELS.items():
            if low <= adjusted_risk < high:
                adjusted_level = level
                break
        risk_analysis["base_risk_score"] = base_risk
        risk_analysis["domain_multiplier"] = domain_multiplier
        risk_analysis["correlation_risk"] = correlation_risk
        risk_analysis["risk_score"] = round(adjusted_risk, 2)
        risk_analysis["risk_level"] = adjusted_level
        risk_analysis["quasi_identifier_analysis"] = quasi_id_analysis
        # Merge quasi-ID recommendations into risk recommendations
        risk_analysis["recommendations"] = (
            risk_analysis.get("recommendations", []) +
            quasi_id_analysis.get("recommendations", [])
        )
        logger.info(
            f"  ✅ Stage 4.5: Quasi-ID — "
            f"{quasi_id_analysis['quasi_id_combinations_found']} correlations, "
            f"re-ID level={quasi_id_analysis['re_identification_level']}, "
            f"adjusted risk={adjusted_risk:.2f} ({adjusted_level})"
        )

        # ── Stage 5: Anonymization ───────────────────────
        anonymized_entities = [self.anonymizer.anonymize(e) for e in classified_entities]
        anonymized_text = self.anonymizer.apply_to_text(text, anonymized_entities)
        token_map = self.anonymizer.get_token_map()
        logger.info(f"  ✅ Stage 5: Anonymization applied ({len(anonymized_entities)} entities)")

        # ── Stage 6: Encryption ──────────────────────────
        encrypted_payload = None
        if self.encrypt_output and self.encryptor:
            encrypted_payload = self.encryptor.encrypt(anonymized_text)
            logger.info(f"  ✅ Stage 6: Encrypted with AES-256-GCM")

        # ── Assemble Result ──────────────────────────────
        elapsed_ms = round((time.time() - start_time) * 1000, 2)

        result = {
            "document_id": doc_id,
            "document_name": document_name,
            "document_type": document_type,
            "metadata": metadata or {},

            # Input stats
            "input_length": len(raw_text),
            "cleaned_length": len(text),

            # Domain Classification (CHANGE 1)
            "domain_classification": domain_info,

            # Detection
            "detection_stats": {
                "regex": len(regex_dets),
                "transformer": len(transformer_dets),
                "spacy": len(spacy_dets),
                "fused": len(fused),
                "after_context_validation": len(recalibrated),
            },

            # Risk (includes quasi-ID correlation from CHANGE 2)
            "risk_analysis": risk_analysis,

            # Entities (anonymized)
            "entities": [
                {
                    "entity_type": e["entity_type"],
                    "original_value": e["value"],
                    "anonymized_value": e.get("anonymized_value", ""),
                    "strategy": e.get("strategy_applied", ""),
                    "confidence": e["confidence"],
                    "sensitivity_level": e.get("sensitivity_level", ""),
                    "sensitivity_weight": e.get("sensitivity_weight", 0),
                    "effective_score": e.get("effective_score", 0),
                    "source": e.get("source", ""),
                    "context_notes": e.get("context_notes", []),
                }
                for e in anonymized_entities
            ],

            # Output
            "anonymized_text": anonymized_text,
            "token_map": token_map,
            "encrypted_payload": encrypted_payload,
            "encryption_key": self.encryptor.get_key_b64() if self.encryptor else None,

            # Meta
            "processing_time_ms": elapsed_ms,
            "anonymization_applied": True,
            "encrypted": bool(encrypted_payload),
        }

        # ── Audit Log ────────────────────────────────────
        if self.audit_logger:
            self.audit_logger.log(result)
            logger.info(f"  ✅ Audit logged → {doc_id}")

        logger.info(f"🏁 Pipeline complete in {elapsed_ms}ms | Risk: {risk_analysis['risk_level']}")
        return result
