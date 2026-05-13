# context/domain_classifier.py
"""
Financial Domain Classifier
============================
Classifies whether a document belongs to the financial domain based on
keyword density analysis and structural heuristics.

Sub-domains detected:
  - BANKING       (account statements, transfers)
  - KYC           (identity verification documents)
  - FINTECH       (UPI, digital payments, wallets)
  - TRANSACTION   (credit/debit logs, receipts)
  - COMPLIANCE    (regulatory filings, audit reports)
  - FRAUD         (fraud reports, suspicious activity)
  - GENERAL       (non-financial fallback)

Research Basis:
  Faculty-directed enhancement — domain-aware contextual privacy intelligence.
"""

import re
from collections import Counter
from typing import Dict, List, Tuple


class FinancialDomainClassifier:
    """
    Keyword-density-based domain classifier for financial documents.
    Uses weighted keyword matching across financial sub-domains to
    determine document type and adjust downstream pipeline behavior.
    """

    # ── Financial Sub-Domain Keyword Sets ────────────────────────────
    DOMAIN_KEYWORDS: Dict[str, List[str]] = {
        "BANKING": [
            "account", "bank", "savings", "current account", "deposit",
            "withdrawal", "balance", "statement", "passbook", "neft",
            "rtgs", "imps", "ifsc", "branch", "cheque", "demand draft",
            "fixed deposit", "recurring deposit", "overdraft", "interest rate",
        ],
        "KYC": [
            "kyc", "know your customer", "identity verification", "aadhaar",
            "pan", "passport", "voter id", "driving license", "proof of identity",
            "proof of address", "ckyc", "video kyc", "ekyc", "re-kyc",
            "beneficial owner", "politically exposed",
        ],
        "FINTECH": [
            "upi", "digital payment", "wallet", "paytm", "phonepe",
            "google pay", "gpay", "razorpay", "fintech", "neobank",
            "prepaid", "qr code", "merchant", "payment gateway",
            "settlement", "payout", "cashback",
        ],
        "TRANSACTION": [
            "transaction", "credited", "debited", "transfer", "payment",
            "receipt", "invoice", "billing", "refund", "emi",
            "instalment", "principal", "outstanding", "due date",
            "transaction id", "reference number", "utr",
        ],
        "COMPLIANCE": [
            "compliance", "regulatory", "rbi", "sebi", "audit",
            "anti-money laundering", "aml", "suspicious transaction",
            "reporting", "disclosure", "dpdp", "gdpr", "pci-dss",
            "data protection", "privacy policy", "consent",
        ],
        "FRAUD": [
            "fraud", "suspicious", "unauthorized", "dispute", "chargeback",
            "phishing", "scam", "identity theft", "compromised",
            "breach", "alert", "blocked", "frozen",
        ],
    }

    # Minimum keyword density to classify as financial document
    FINANCIAL_THRESHOLD = 0.005   # 0.5% of words must be financial keywords
    # Minimum hits to assign a sub-domain
    SUBDOMAIN_MIN_HITS = 2

    def classify(self, text: str) -> Dict:
        """
        Classify a document's financial domain.

        Returns:
            dict with keys:
                - is_financial (bool): Whether the document is financial
                - domain (str): Primary sub-domain or 'GENERAL'
                - sub_domains (list): All matched sub-domains with scores
                - domain_confidence (float): 0.0–1.0 confidence in classification
                - keyword_density (float): Financial keyword density in document
                - financial_keywords_found (list): Matched keywords
        """
        text_lower = text.lower()
        words = text_lower.split()
        word_count = max(len(words), 1)

        # ── Count keyword hits per sub-domain ───────────────────
        domain_hits: Dict[str, List[str]] = {}
        all_financial_keywords: List[str] = []

        for domain, keywords in self.DOMAIN_KEYWORDS.items():
            hits = []
            for kw in keywords:
                # Count occurrences (phrase-level matching)
                count = text_lower.count(kw)
                if count > 0:
                    hits.extend([kw] * count)
            domain_hits[domain] = hits
            all_financial_keywords.extend(hits)

        # ── Compute density and confidence ──────────────────────
        total_financial_hits = len(all_financial_keywords)
        keyword_density = total_financial_hits / word_count

        is_financial = keyword_density >= self.FINANCIAL_THRESHOLD

        # ── Rank sub-domains ────────────────────────────────────
        domain_scores = {
            domain: len(hits)
            for domain, hits in domain_hits.items()
            if len(hits) >= self.SUBDOMAIN_MIN_HITS
        }

        # Sort by hit count descending
        ranked_domains = sorted(domain_scores.items(), key=lambda x: x[1], reverse=True)

        primary_domain = ranked_domains[0][0] if ranked_domains else "GENERAL"
        if not is_financial:
            primary_domain = "GENERAL"

        # Confidence based on density (sigmoid-like scaling)
        # density of 0.01 → ~0.6, density of 0.05 → ~0.95
        domain_confidence = min(1.0, keyword_density * 20) if is_financial else 0.0

        return {
            "is_financial": is_financial,
            "domain": primary_domain,
            "sub_domains": [
                {"domain": d, "score": s} for d, s in ranked_domains
            ],
            "domain_confidence": round(domain_confidence, 4),
            "keyword_density": round(keyword_density, 6),
            "financial_keywords_found": list(set(all_financial_keywords)),
        }

    def get_domain_risk_multiplier(self, domain: str) -> float:
        """
        Returns a risk multiplier based on the financial sub-domain.
        Higher-risk domains get higher multipliers for sensitivity scoring.
        """
        multipliers = {
            "BANKING":     1.3,
            "KYC":         1.4,
            "FINTECH":     1.2,
            "TRANSACTION": 1.1,
            "COMPLIANCE":  1.5,
            "FRAUD":       1.6,
            "GENERAL":     1.0,
        }
        return multipliers.get(domain, 1.0)
