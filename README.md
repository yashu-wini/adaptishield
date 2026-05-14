# 🛡️ AdaptiShield

### Context-Aware Privacy Intelligence Framework

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Detect · Classify · Anonymize · Encrypt**

A modular, 6-stage pipeline that combines Regex, Transformer (DeBERTa-v3), and spaCy NER to detect PII in text and documents — then validates, risk-scores, anonymizes, and encrypts the output.

---

## ✨ Features

- **Hybrid Detection** — Regex (high precision) + DeBERTa-v3 Transformer (high recall) + spaCy NER, merged via a Fusion Engine with floor-guaranteed confidence boosting
- **Indian PII Support** — Aadhaar, PAN, Voter ID, Driving License, Passport, IFSC, UPI ID, GST Number, Pincode
- **Generic PII Support** — Email, Phone, Credit Card (Luhn-validated), Bank Account, IP Address, Password, URL, Date, Name
- **Preceding Label Analysis** — General-purpose false positive filter: if a PII match follows a non-confirming label (e.g., `Tracking:`, `Order ID:`, `Serial:`), it's rejected. No hardcoded label lists — uses the entity's own positive context keywords to decide
- **Smart Regex Validation** — PASSWORD complexity checks (rejects "password policy:"), IP address filtering (0.0.0.0, subnet masks), PAN context requirement, PINCODE address-context gating, phone version-prefix detection ("Python 3.9876543210")
- **Context Validation** — ±120 char semantic window analysis with positive/negative signals, structured PII co-occurrence checks, and cross-detector agreement scoring
- **Quasi-Identifier Correlation** — Detects dangerous entity combinations (e.g., Aadhaar + PAN + Name) with superset deduplication to prevent double-counting
- **Risk Scoring** — Evidence-backed per-entity sensitivity (ITRC, BreachRadar, Dark Web studies) and document-level risk scoring with compliance recommendations
- **Adaptive Anonymization** — 6 strategies: MASK, TOKENIZE, REDACT, PSEUDONYMIZE, GENERALIZE, K-ANONYMIZE — policy-driven by sensitivity level
- **AES-256-GCM Encryption** — Authenticated encryption of anonymized output with fresh nonces
- **Multi-format Ingestion** — PDF, DOCX, CSV/XLSX, and plain text with OCR artifact correction
- **Web Dashboard** — Glassmorphism dark-theme SPA with live pipeline visualization, entity explorer, and audit logs
- **REST API** — FastAPI with Swagger/ReDoc documentation, JWT auth for sensitive endpoints
- **Audit Trail** — Every analysis is logged with document ID, risk level, entity count, and timestamp

---

## 📐 Architecture

```
User Input (Text / PDF / DOCX / CSV)
        │
        ▼
┌───────────────────────────────────────────────────┐
│  Stage 1: INGESTION                               │
│  PDF / DOCX / CSV parsers → TextCleaner           │
│  (Unicode norm, OCR artifact fix, whitespace)     │
└─────────────────────┬─────────────────────────────┘
                      ▼
┌───────────────────────────────────────────────────┐
│  Stage 2: HYBRID DETECTION                        │
│  Regex ──┐                                        │
│  DeBERTa ├──→ Fusion Engine (IoU dedup +          │
│  spaCy ──┘    floor-guaranteed confidence boost)  │
│  + Smart validation: Luhn, IP filter, PASSWORD    │
│    complexity, PAN/PINCODE confidence gating      │
└─────────────────────┬─────────────────────────────┘
                      ▼
┌───────────────────────────────────────────────────┐
│  Stage 3: CONTEXT VALIDATION                      │
│  ┌─ Preceding Label Analysis ──────────────────┐  │
│  │  "Tracking: 4532..." → label ≠ CREDIT_CARD  │  │
│  │  positive context → REJECT (0.20× penalty)  │  │
│  └─────────────────────────────────────────────┘  │
│  + Positive/negative context signals (±120 chars) │
│  + Entity-specific: PAN context, phone version    │
│    prefix, password complexity, pincode address    │
│  + Structured PII co-occurrence filtering         │
│  + Cross-detector agreement scoring               │
│  → ConfidenceEngine (co-occurrence boosts)        │
└─────────────────────┬─────────────────────────────┘
                      ▼
┌───────────────────────────────────────────────────┐
│  Stage 4: SENSITIVITY & RISK SCORING              │
│  Evidence-backed risk profiles (ITRC/BreachRadar) │
│  effective_score = weight × confidence            │
│  risk_score = Σ(effective_scores)                 │
│  → LOW / MEDIUM / HIGH / CRITICAL                 │
├───────────────────────────────────────────────────┤
│  Stage 4.5: QUASI-ID CORRELATION                  │
│  Detects dangerous entity combos (Rocher et al.)  │
│  Superset deduplication (no double-counting)      │
│  final_risk = base_risk + correlation_risk        │
└─────────────────────┬─────────────────────────────┘
                      ▼
┌───────────────────────────────────────────────────┐
│  Stage 5: ANONYMIZATION                           │
│  LOW → MASK  | MEDIUM → TOKENIZE                  │
│  HIGH/CRITICAL → REDACT                           │
│  + PSEUDONYMIZE / GENERALIZE / K_ANONYMIZE        │
└─────────────────────┬─────────────────────────────┘
                      ▼
┌───────────────────────────────────────────────────┐
│  Stage 6: AES-256-GCM ENCRYPTION                  │
│  Fresh 96-bit nonce per encryption                │
│  → base64 ciphertext + nonce                      │
└─────────────────────┬─────────────────────────────┘
                      ▼
              Audit Logger → Database
              API Response → Dashboard
```

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.10+**
- **pip** (package manager)
- *(Optional)* A virtual environment tool (`venv`, `conda`, etc.)

### 1. Clone the Repository

```bash
git clone https://github.com/yashu-wini/adaptishield.git
cd adaptishield
```

### 2. Create a Virtual Environment (recommended)

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r adaptishield/requirements.txt
```

> **Note:** The Transformer detector requires `torch` and `transformers`, which are large packages. If you only want to run the regex-based pipeline (much faster, no GPU needed), these are still listed in requirements but you can skip loading them at runtime — the pipeline supports `use_transformer=False`.

### 4. Download spaCy Model (if using spaCy detector)

```bash
python -m spacy download en_core_web_sm
```

---

## 🖥️ Usage

AdaptiShield can be used in **three ways**: the Web Dashboard, the CLI Demo, or the Python API directly.

### Option A: Web Dashboard + REST API

Start the FastAPI server:

```bash
cd adaptishield
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload
```

Then open your browser:

| URL | Description |
|-----|-------------|
| [http://127.0.0.1:8000](http://127.0.0.1:8000) | 🖥️ Web Dashboard (interactive UI) |
| [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) | 📖 Swagger API Documentation |
| [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc) | 📘 ReDoc API Documentation |

**Dashboard Pages:**
- **Overview** — Live metrics, recent analyses, entity breakdown chart, audit feed
- **Analyze** — Paste text or use sample inputs, see the full pipeline in action
- **Pipeline** — Visual architecture diagram with supported PII types
- **Entities** — Aggregated entity explorer across all analyses
- **Anonymization** — Strategy policy table and transformation history
- **Audit Logs** — Full compliance trail

### Option B: CLI Demo

Run the demo script for a quick terminal-based walkthrough with 3 sample test cases:

```bash
cd adaptishield
python demo.py
```

This runs three scenarios (Personal Record, KYC Document, Critical Password Leak) through the full pipeline and prints color-coded results using the `rich` library.

To also run the test suite via the demo:

```bash
python demo.py --test
```

### Option C: Python API (in your own code)

```python
from pipeline import AdaptiShieldPipeline

# Initialize (set use_transformer=True for DeBERTa, use_spacy=True for spaCy NER)
pipeline = AdaptiShieldPipeline(
    use_transformer=False,  # Set True if you have the model downloaded
    use_spacy=False,        # Set True if spaCy model is installed
    encrypt_output=True,
    log_results=True
)

# Analyze text
result = pipeline.process_text(
    "Name: Priya Mehta | Aadhaar: 2345 6789 0123 | Email: priya@gmail.com",
    document_name="kyc_document"
)

# Access results
print(f"Risk Level: {result['risk_analysis']['risk_level']}")
print(f"Risk Score: {result['risk_analysis']['risk_score']}")
print(f"Entities Found: {len(result['entities'])}")
print(f"Anonymized Text: {result['anonymized_text']}")

# Analyze a file
result = pipeline.process_file("path/to/document.pdf")
```

---

## 🔌 REST API Reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/` | — | Serves the web dashboard |
| `GET` | `/health` | — | Health check (`{"status": "healthy"}`) |
| `POST` | `/auth/login` | — | Get a JWT token (username + password) |
| `POST` | `/analyze/text` | — | Analyze plain text for PII |
| `POST` | `/analyze/file` | — | Upload and analyze a document |
| `GET` | `/logs/recent?limit=20` | — | Fetch recent audit log entries |
| `POST` | `/decrypt` | JWT (admin) | Decrypt an encrypted payload |

**Example — Analyze Text:**

```bash
curl -X POST http://127.0.0.1:8000/analyze/text \
  -H "Content-Type: application/json" \
  -d '{"text": "My Aadhaar is 2345 6789 0123 and email is test@mail.com"}'
```

**Example — Upload File:**

```bash
curl -X POST http://127.0.0.1:8000/analyze/file \
  -F "file=@document.pdf"
```

**Default Credentials** (for `/auth/login` and `/decrypt`):

| Username | Password | Role |
|----------|----------|------|
| `admin` | `admin123` | Admin (can decrypt) |
| `analyst` | `analyst123` | Analyst |

---

## 🧪 Running Tests

```bash
cd adaptishield

# Unit tests (21 tests)
python -m unittest tests.test_pipeline -v

# Edge case tests (22 tests)
python test_edge_cases.py
```

**Unit test suite** (21 tests):
- Regex detection accuracy (Email, Aadhaar, PAN, Phone, Credit Card with Luhn validation)
- False positive rejection on clean text
- Sensitivity classification thresholds
- Anonymization strategies (masking, tokenization, redaction)
- AES-256-GCM encrypt/decrypt roundtrips
- Fusion engine confidence boosting
- Full end-to-end pipeline integration

**Edge case test suite** (22 tests) — verifies false positive rejection:

| Test | Input | Expected |
|------|-------|----------|
| Tracking number | `Tracking: 4532015112830366` (valid Luhn) | ❌ NOT credit card |
| Order ID | `Order ID: 2345 6789 0123` | ❌ NOT Aadhaar |
| Serial number | `Serial: 9876543210` | ❌ NOT phone |
| Version number | `Python 3.9876543210` | ❌ NOT phone |
| Policy number | `Policy Number: 4532015112830366` | ❌ NOT credit card |
| Password policy | `password policy: minimum 8 chars` | ❌ NOT password |
| Algorithm name | `The ABCDE1234F algorithm` | ❌ NOT PAN |
| Null IP | `0.0.0.0` | ❌ NOT IP address |
| Real credit card | `Credit Card: 4532015112830366` | ✅ Detected |
| Real Aadhaar | `Aadhaar: 2345 6789 0123` | ✅ Detected |
| Real password | `password: Secret@123!` | ✅ Detected |
| Natural language | `My account number is 12345678901234` | ✅ Detected |

---

## 📁 Project Structure

```
adaptishield/
├── pipeline.py                 # Core 6-stage pipeline orchestrator
├── demo.py                     # CLI demo with rich terminal output
├── requirements.txt            # Python dependencies
├── __init__.py
│
├── api/                        # REST API (FastAPI)
│   ├── main.py                 # Routes, static file serving
│   └── auth.py                 # JWT auth, password hashing (bcrypt)
│
├── static/                     # Web dashboard (vanilla HTML/CSS/JS)
│   ├── index.html              # Multi-page SPA
│   ├── style.css               # Dark glassmorphism theme
│   └── app.js                  # Client-side logic & API calls
│
├── detection/                  # Hybrid PII detection
│   ├── regex_detector.py       # Pattern-based + smart validation
│   ├── transformer_detector.py # DeBERTa-v3 NER (high recall)
│   ├── spacy_detector.py       # spaCy NER (named entities)
│   └── fusion_engine.py        # IoU dedup + floor-guaranteed boosting
│
├── context/                    # Semantic validation & intelligence
│   ├── context_validator.py    # Preceding label analysis + ±120 char window
│   ├── confidence_engine.py    # Co-occurrence boosts
│   ├── domain_classifier.py    # Financial sub-domain classification
│   └── quasi_identifier_engine.py  # Re-identification risk correlation
│
├── sensitivity/                # Risk scoring
│   └── sensitivity_classifier.py
│
├── anonymization/              # Adaptive data masking
│   └── masking.py              # MASK / TOKENIZE / REDACT engines
│
├── security/                   # Cryptographic protection
│   └── aes_encryptor.py        # AES-256-GCM encryption
│
├── database/                   # Audit logging
│   ├── logger.py               # Audit log writer
│   └── models.py               # Database schema
│
├── configs/                    # Configuration
│   ├── pii_config.py           # PII patterns, weights, policies
│   └── settings.py             # App settings
│
├── ingestion/                  # Document parsing
│   ├── pdf_parser.py
│   ├── docx_parser.py
│   ├── csv_parser.py
│   └── text_cleaner.py
│
├── dashboard/                  # Streamlit dashboard (alternative)
│   └── app.py
│
└── tests/
    └── test_pipeline.py        # Full test suite
```

---

## 🔐 Supported PII Types

### Indian-Specific

| Type | Example | Sensitivity |
|------|---------|-------------|
| Aadhaar | `2345 6789 0123` | 🔴 CRITICAL |
| PAN | `ABCDE1234F` | 🟠 HIGH |
| Passport | `A1234567` | 🟠 HIGH |
| Voter ID | `ABC1234567` | 🟠 HIGH |
| Driving License | `KA0120201234567` | 🟡 MEDIUM |
| UPI ID | `user@upi` | 🟡 MEDIUM |
| IFSC Code | `SBIN0001234` | 🟡 MEDIUM |
| GST Number | `29ABCDE1234F1Z5` | 🟢 LOW |
| Pincode | `560001` | 🟢 LOW |

### Generic

| Type | Example | Sensitivity |
|------|---------|-------------|
| Password | `Secure@123!` | 🔴 CRITICAL |
| Credit Card | `4532015112830366` (Luhn-validated) | 🔴 CRITICAL |
| Bank Account | `1234567890123` | 🟠 HIGH |
| Medical Record | `MRN-12345` | 🟠 HIGH |
| Email | `user@domain.com` | 🟡 MEDIUM |
| Phone | `+91-9876543210` | 🟡 MEDIUM |
| IP Address | `192.168.1.1` | 🟡 MEDIUM |
| Name | `John Smith` | 🟢 LOW |

---

## ⚙️ Anonymization Strategies

| Sensitivity Level | Strategy | Example |
|-------------------|----------|---------|
| 🟢 LOW | **MASK** | `j***@gmail.com` |
| 🟡 MEDIUM | **TOKENIZE** | `PHONE_TOKEN_3F8A` |
| 🟠 HIGH | **REDACT** | `[PAN_REDACTED]` |
| 🔴 CRITICAL | **REDACT** | `[AADHAAR_REDACTED]` |

---

## 📄 License

This project is open-source and available under the [MIT License](LICENSE).

---

**Built with ❤️ for privacy compliance**

*AdaptiShield — because data privacy isn't optional.*
