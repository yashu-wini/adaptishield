# configs/pii_config.py
# PII Entity Definitions, Sensitivity Weights, and Policies

# Evidence-Backed Risk Profiles (Derived from ITRC, BreachRadar, Dark Web Studies)
# Final Risk = 0.3(Exposure) + 0.3(FraudImpact) + 0.2(Regulatory) + 0.2(AbuseLikelihood)
ENTITY_RISK_PROFILE = {
    # Financial PII
    "CREDIT_CARD":     {"exposure_frequency": 0.85, "fraud_impact": 0.95, "regulatory_severity": 1.00, "abuse_likelihood": 0.98},
    "BANK_ACCOUNT":    {"exposure_frequency": 0.60, "fraud_impact": 0.90, "regulatory_severity": 0.95, "abuse_likelihood": 0.85},
    "UPI_ID":          {"exposure_frequency": 0.70, "fraud_impact": 0.65, "regulatory_severity": 0.60, "abuse_likelihood": 0.80},
    "IFSC_CODE":       {"exposure_frequency": 0.80, "fraud_impact": 0.20, "regulatory_severity": 0.20, "abuse_likelihood": 0.15},

    # Government / Legal IDs
    "AADHAAR":         {"exposure_frequency": 0.65, "fraud_impact": 0.95, "regulatory_severity": 1.00, "abuse_likelihood": 0.90},
    "PAN":             {"exposure_frequency": 0.75, "fraud_impact": 0.85, "regulatory_severity": 0.90, "abuse_likelihood": 0.80},
    "PASSPORT":        {"exposure_frequency": 0.40, "fraud_impact": 0.90, "regulatory_severity": 0.95, "abuse_likelihood": 0.75},
    "VOTER_ID":        {"exposure_frequency": 0.70, "fraud_impact": 0.40, "regulatory_severity": 0.50, "abuse_likelihood": 0.30},
    "DRIVING_LICENSE": {"exposure_frequency": 0.55, "fraud_impact": 0.60, "regulatory_severity": 0.70, "abuse_likelihood": 0.50},
    "GST_NUMBER":      {"exposure_frequency": 0.80, "fraud_impact": 0.30, "regulatory_severity": 0.40, "abuse_likelihood": 0.25},

    # Personal Identifiers (KYC Context)
    "EMAIL":           {"exposure_frequency": 0.95, "fraud_impact": 0.50, "regulatory_severity": 0.40, "abuse_likelihood": 0.85},
    "PHONE":           {"exposure_frequency": 0.90, "fraud_impact": 0.60, "regulatory_severity": 0.50, "abuse_likelihood": 0.80},
    "NAME":            {"exposure_frequency": 0.98, "fraud_impact": 0.30, "regulatory_severity": 0.30, "abuse_likelihood": 0.40},
    "ADDRESS":         {"exposure_frequency": 0.60, "fraud_impact": 0.40, "regulatory_severity": 0.40, "abuse_likelihood": 0.40},
    "DATE_OF_BIRTH":   {"exposure_frequency": 0.70, "fraud_impact": 0.55, "regulatory_severity": 0.50, "abuse_likelihood": 0.60},
    "AGE":             {"exposure_frequency": 0.65, "fraud_impact": 0.10, "regulatory_severity": 0.10, "abuse_likelihood": 0.10},
    "GENDER":          {"exposure_frequency": 0.85, "fraud_impact": 0.05, "regulatory_severity": 0.10, "abuse_likelihood": 0.05},
}

ANONYMIZATION_POLICY = {
    "LOW":    "MASK",           # r***@gmail.com
    "MEDIUM": "TOKENIZE",       # PHONE_TOKEN_21
    "HIGH":   "REDACT",         # [REDACTED]
    "CRITICAL": "REDACT",       # [REDACTED]
}

# Research-backed anonymization strategies (CHANGE 3)
# These can be selected programmatically based on entity type and domain context
RESEARCH_ANONYMIZATION_STRATEGIES = {
    "PSEUDONYMIZE":  "Replace with consistent reversible pseudonyms (Roopalakshmi, 2026)",
    "GENERALIZE":    "Reduce precision — dates→month/year, age→range, PIN→partial",
    "K_ANONYMIZE":   "Generalize quasi-identifiers into equivalence classes (Li et al., 2021)",
    "MASK":          "Structure-preserving masking",
    "TOKENIZE":      "Deterministic hash-based tokens (reversible)",
    "REDACT":        "Full suppression / removal (irreversible)",
}

# Quasi-identifier entity types (benefit from k-anonymity / generalization)
QUASI_IDENTIFIER_TYPES = {
    "AGE", "PINCODE", "DATE", "DATE_OF_BIRTH",
    "LOCATION", "ADDRESS", "GENDER",
}

RISK_LEVELS = {
    "LOW":      (0, 25),
    "MEDIUM":   (25, 50),
    "HIGH":     (50, 75),
    "CRITICAL": (75, float("inf")),
}

# Indian-specific regex patterns
INDIAN_PII_PATTERNS = {
    "AADHAAR": r"\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b",
    "PAN":     r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
    "VOTER_ID": r"\b[A-Z]{3}[0-9]{7}\b",
    "DRIVING_LICENSE": r"\b[A-Z]{2}[0-9]{2}\s?[0-9]{11}\b",
    "PASSPORT": r"\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b",
    "IFSC_CODE": r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
    "UPI_ID": r"\b[\w.\-]{2,256}@(?:ybl|upi|okhdfcbank|okaxis|oksbi|okicici|apl|ibl|paytm|axl|sbi|hdfcbank|icici|fbl|kotak|axisbank|indus|boi|pnb|federal|rbl|idbi|cnrb)\b",
    "GST_NUMBER": r"\b\d{2}[A-Z]{5}\d{4}[A-Z]{1}[A-Z\d]{1}[Z]{1}[A-Z\d]{1}\b",
    "PINCODE": r"\b[1-9][0-9]{5}\b",
}

GENERIC_PII_PATTERNS = {
    "EMAIL":        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    "PHONE":        r"\b(?:\+91[\-\s]?)?[6-9]\d{9}\b|\b(?:\+1[\-\s]?)?\(?\d{3}\)?[\-\s]?\d{3}[\-\s]?\d{4}\b",
    "CREDIT_CARD":  r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b",
    "BANK_ACCOUNT": r"(?i)(?:account|a\/c|acct)[\s.:=#-]*([0-9]{9,18})\b",
    "DATE":         r"\b(?:\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}|\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2})\b",
}
