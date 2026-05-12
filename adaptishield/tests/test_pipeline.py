# tests/test_pipeline.py
"""
AdaptiShield Test Suite
Tests each stage of the pipeline independently and end-to-end.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import unittest
from detection.regex_detector import RegexDetector
from context.context_validator import ContextValidator
from sensitivity.sensitivity_classifier import SensitivityClassifier
from anonymization.masking import MaskingEngine, TokenizationEngine, AdaptiveAnonymizer
from security.aes_encryptor import AESEncryptor
from detection.fusion_engine import FusionEngine
from ingestion.text_cleaner import TextCleaner


class TestRegexDetector(unittest.TestCase):

    def setUp(self):
        self.detector = RegexDetector()

    def test_email_detection(self):
        text = "Contact me at john.doe@gmail.com for info."
        results = self.detector.detect(text)
        emails = [r for r in results if r["entity_type"] == "EMAIL"]
        self.assertTrue(len(emails) >= 1)
        self.assertEqual(emails[0]["value"], "john.doe@gmail.com")

    def test_aadhaar_detection(self):
        text = "My Aadhaar number is 2345 6789 0123."
        results = self.detector.detect(text)
        aadhaar = [r for r in results if r["entity_type"] == "AADHAAR"]
        self.assertTrue(len(aadhaar) >= 1)

    def test_pan_detection(self):
        text = "PAN card: ABCDE1234F"
        results = self.detector.detect(text)
        pan = [r for r in results if r["entity_type"] == "PAN"]
        self.assertTrue(len(pan) >= 1)
        self.assertAlmostEqual(pan[0]["confidence"], 0.95, places=1)

    def test_phone_detection(self):
        text = "Call me at +91-9876543210"
        results = self.detector.detect(text)
        phones = [r for r in results if r["entity_type"] == "PHONE"]
        self.assertTrue(len(phones) >= 1)

    def test_credit_card_luhn_valid(self):
        text = "Card: 4532015112830366"  # Valid Luhn
        results = self.detector.detect(text)
        cards = [r for r in results if r["entity_type"] == "CREDIT_CARD"]
        self.assertTrue(len(cards) >= 1)

    def test_credit_card_luhn_invalid(self):
        text = "Number: 4532015112830000"  # Invalid Luhn
        results = self.detector.detect(text)
        cards = [r for r in results if r["entity_type"] == "CREDIT_CARD"]
        self.assertEqual(len(cards), 0)

    def test_no_false_positives_on_clean_text(self):
        text = "The weather today is nice. I love programming."
        results = self.detector.detect(text)
        self.assertEqual(len(results), 0)


class TestSensitivityClassifier(unittest.TestCase):

    def setUp(self):
        self.classifier = SensitivityClassifier()

    def test_aadhaar_is_critical(self):
        detection = {
            "entity_type": "AADHAAR",
            "value": "2345 6789 0123",
            "confidence": 0.90,
            "start": 0, "end": 14, "source": "regex"
        }
        classified = self.classifier.classify_entity(detection)
        self.assertIn(classified["sensitivity_level"], ["HIGH", "CRITICAL"])

    def test_name_is_low(self):
        detection = {
            "entity_type": "NAME",
            "value": "John",
            "confidence": 0.75,
            "start": 0, "end": 4, "source": "spacy"
        }
        classified = self.classifier.classify_entity(detection)
        self.assertIn(classified["sensitivity_level"], ["LOW", "MEDIUM"])

    def test_document_risk_score_positive(self):
        detections = [
            {"entity_type": "AADHAAR", "value": "2345 6789 0123", "confidence": 0.90, "start": 0, "end": 14, "source": "regex"},
            {"entity_type": "PAN", "value": "ABCDE1234F", "confidence": 0.95, "start": 20, "end": 30, "source": "regex"},
        ]
        result = self.classifier.classify_document(detections)
        self.assertGreater(result["risk_score"], 0)
        self.assertIn(result["risk_level"], ["HIGH", "CRITICAL"])


class TestAnonymization(unittest.TestCase):

    def setUp(self):
        self.masker = MaskingEngine()
        self.tokenizer = TokenizationEngine()

    def test_email_masking(self):
        masked = self.masker.mask("john.doe@gmail.com", "EMAIL")
        self.assertIn("@gmail.com", masked)
        self.assertIn("***", masked)
        self.assertNotIn("john.doe", masked)

    def test_phone_masking(self):
        masked = self.masker.mask("9876543210", "PHONE")
        self.assertIn("****", masked)

    def test_tokenization_deterministic(self):
        token1 = self.tokenizer.tokenize("9876543210", "PHONE")
        token2 = self.tokenizer.tokenize("9876543210", "PHONE")
        self.assertEqual(token1, token2)
        self.assertIn("PHONE_TOKEN_", token1)

    def test_tokenization_reversible(self):
        original = "test@example.com"
        token = self.tokenizer.tokenize(original, "EMAIL")
        recovered = self.tokenizer.detokenize(token)
        self.assertEqual(recovered, original)

    def test_adaptive_anonymizer_applies_correct_strategy(self):
        anon = AdaptiveAnonymizer()
        detection = {
            "entity_type": "AADHAAR",
            "value": "2345 6789 0123",
            "sensitivity_level": "CRITICAL",
            "anonymization_strategy": "REDACT",
            "confidence": 0.90, "start": 0, "end": 14
        }
        result = anon.anonymize(detection)
        self.assertIn("REDACTED", result["anonymized_value"])


class TestEncryption(unittest.TestCase):

    def test_encrypt_decrypt_roundtrip(self):
        enc = AESEncryptor()
        plaintext = "Hello, this is sensitive data."
        payload = enc.encrypt(plaintext)
        decrypted = enc.decrypt(payload)
        self.assertEqual(decrypted, plaintext)

    def test_different_nonces_each_time(self):
        enc = AESEncryptor()
        p1 = enc.encrypt("same text")
        p2 = enc.encrypt("same text")
        self.assertNotEqual(p1["nonce"], p2["nonce"])
        self.assertNotEqual(p1["ciphertext"], p2["ciphertext"])

    def test_key_export_import(self):
        enc = AESEncryptor()
        key_b64 = enc.get_key_b64()
        enc2 = AESEncryptor.from_key_b64(key_b64)
        payload = enc.encrypt("test data")
        decrypted = enc2.decrypt(payload)
        self.assertEqual(decrypted, "test data")


class TestFusionEngine(unittest.TestCase):

    def test_fusion_boosts_confidence_on_agreement(self):
        fusion = FusionEngine()
        regex_det = [{"entity_type": "EMAIL", "value": "a@b.com", "start": 0, "end": 7, "confidence": 0.90, "source": "regex"}]
        transformer_det = [{"entity_type": "EMAIL", "value": "a@b.com", "start": 0, "end": 7, "confidence": 0.85, "source": "transformer"}]
        fused = fusion.fuse(regex_det, transformer_det, [])
        self.assertEqual(len(fused), 1)
        self.assertGreater(fused[0]["confidence"], 0.90)

    def test_non_overlapping_kept_separate(self):
        fusion = FusionEngine()
        d1 = [{"entity_type": "EMAIL", "value": "a@b.com", "start": 0, "end": 7, "confidence": 0.90, "source": "regex"}]
        d2 = [{"entity_type": "PHONE", "value": "9876543210", "start": 20, "end": 30, "confidence": 0.88, "source": "regex"}]
        fused = fusion.fuse(d1, d2, [])
        self.assertEqual(len(fused), 2)


class TestEndToEnd(unittest.TestCase):

    def test_full_pipeline_text(self):
        """Test complete pipeline without transformer (fast)."""
        from pipeline import AdaptiShieldPipeline
        p = AdaptiShieldPipeline(use_transformer=False, use_spacy=False, encrypt_output=True)
        text = "Hello, I am Ravi Kumar. Email: ravi@gmail.com, Phone: +91-9876543210, Aadhaar: 2345 6789 0123"
        result = p.process_text(text)

        self.assertIn("risk_analysis", result)
        self.assertIn("entities", result)
        self.assertIn("anonymized_text", result)
        self.assertGreater(result["risk_analysis"]["entity_count"], 0)
        self.assertIsNotNone(result["encrypted_payload"])
        self.assertGreater(len(result["entities"]), 0)

        # Verify anonymization applied
        anon_text = result["anonymized_text"]
        self.assertNotIn("ravi@gmail.com", anon_text)
        self.assertNotIn("2345 6789 0123", anon_text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
