# configs/pii_config.py
# PII Entity Definitions, Sensitivity Weights, and Policies

PII_SENSITIVITY_WEIGHTS = {
    # Personal Identifiers
    "NAME":             10,
    "EMAIL":            20,
    "PHONE":            30,
    "ADDRESS":          25,
    "DATE_OF_BIRTH":    35,
    "AGE":              15,
    "GENDER":           10,

    # Financial
    "CREDIT_CARD":      80,
    "BANK_ACCOUNT":     75,
    "UPI_ID":           60,
    "IFSC_CODE":        50,

    # Government / Indian PII
    "PAN":              60,
    "AADHAAR":          90,
    "PASSPORT":         85,
    "VOTER_ID":         70,
    "DRIVING_LICENSE":  65,
    "GST_NUMBER":       45,

    # Medical
    "MEDICAL_RECORD":   95,
    "DIAGNOSIS":        85,
    "PRESCRIPTION":     80,

    # Digital
    "IP_ADDRESS":       40,
    "URL":              10,
    "USERNAME":         25,
    "PASSWORD":         100,

    # Organization
    "ORGANIZATION":     5,
    "LOCATION":         10,
}

ANONYMIZATION_POLICY = {
    "LOW":    "MASK",       # r***@gmail.com
    "MEDIUM": "TOKENIZE",   # PHONE_TOKEN_21
    "HIGH":   "REDACT",     # [REDACTED]
    "CRITICAL": "REDACT",   # [REDACTED]
}

RISK_LEVELS = {
    "LOW":      (0, 30),
    "MEDIUM":   (30, 70),
    "HIGH":     (70, 150),
    "CRITICAL": (150, float("inf")),
}

# Indian-specific regex patterns
INDIAN_PII_PATTERNS = {
    "AADHAAR": r"\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b",
    "PAN":     r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
    "VOTER_ID": r"\b[A-Z]{3}[0-9]{7}\b",
    "DRIVING_LICENSE": r"\b[A-Z]{2}[0-9]{2}\s?[0-9]{11}\b",
    "PASSPORT": r"\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b",
    "IFSC_CODE": r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
    "UPI_ID": r"\b[\w.\-]{2,256}@[a-zA-Z]{2,64}\b",
    "GST_NUMBER": r"\b\d{2}[A-Z]{5}\d{4}[A-Z]{1}[A-Z\d]{1}[Z]{1}[A-Z\d]{1}\b",
    "PINCODE": r"\b[1-9][0-9]{5}\b",
}

GENERIC_PII_PATTERNS = {
    "EMAIL":        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    "PHONE":        r"\b(?:\+91[\-\s]?)?[6-9]\d{9}\b|\b(?:\+1[\-\s]?)?\(?\d{3}\)?[\-\s]?\d{3}[\-\s]?\d{4}\b",
    "IP_ADDRESS":   r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "CREDIT_CARD":  r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b",
    "BANK_ACCOUNT": r"\b[0-9]{9,18}\b",
    "DATE":         r"\b(?:\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}|\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2})\b",
    "URL":          r"https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)",
    "PASSWORD":     r"(?i)(?:password|passwd|pwd)[\s:=]+\S+",
    "USERNAME":     r"(?i)(?:username|user|login)[\s:=]+\S+",
}
