# AdaptiShield — Codebase Meta-Explanation

## 1. Overview

**AdaptiShield** is a context-aware privacy intelligence framework designed to detect, classify, and anonymize Personally Identifiable Information (PII) within text and documents. It operates as a **6-stage pipeline**, combining deterministic methods (Regex) with advanced NLP (spaCy) and Deep Learning Transformer models (DeBERTa-v3) to ensure robust PII detection. After detection, the framework applies context validation, risk scoring, adaptive anonymization, and AES-256-GCM encryption.

The project is structured modularly, allowing integration into existing enterprise applications through its **FastAPI REST API**, its **Streamlit analytics dashboard**, or the new **custom web dashboard** served directly from the API.

---

## 2. Directory Structure

```
adaptishield/
├── pipeline.py                  # Core pipeline orchestrator (all 6 stages)
├── demo.py                      # CLI demo script (rich library)
├── requirements.txt             # Python dependencies
├── Dockerfile                   # Docker container definition
├── docker-compose.yml           # Docker Compose service config
├── __init__.py
│
├── api/                         # REST API layer (FastAPI)
│   ├── main.py                  # FastAPI app, routes, static file serving
│   ├── auth.py                  # JWT creation, password hashing
│   └── __init__.py
│
├── static/                      # NEW — Custom web dashboard (vanilla HTML/CSS/JS)
│   ├── index.html               # Multi-page SPA dashboard
│   ├── style.css                # Dark glassmorphism theme
│   └── app.js                   # Client-side logic, API integration
│
├── dashboard/                   # Streamlit analytics dashboard (original)
│   ├── app.py                   # Streamlit app with Plotly charts
│   └── __init__.py
│
├── configs/                     # Configuration & policy definitions
│   ├── pii_config.py            # PII patterns, sensitivity weights, policies
│   ├── settings.py              # Environment and app settings
│   └── __init__.py
│
├── ingestion/                   # Document parsing & text extraction
│   ├── pdf_parser.py            # PDF text extraction
│   ├── docx_parser.py           # DOCX text extraction
│   ├── csv_parser.py            # CSV/XLSX text extraction
│   ├── text_cleaner.py          # Unicode normalization, whitespace cleanup
│   └── __init__.py
│
├── detection/                   # Hybrid PII detection engine
│   ├── regex_detector.py        # Pattern-based detection (high precision)
│   ├── transformer_detector.py  # DeBERTa-v3 NER (high recall)
│   ├── spacy_detector.py        # spaCy NER (named entities)
│   ├── fusion_engine.py         # Merges, deduplicates, boosts confidence
│   └── __init__.py
│
├── context/                     # Semantic validation & confidence tuning
│   ├── context_validator.py     # Positive/negative context signals
│   ├── confidence_engine.py     # Co-occurrence boosts, recalibration
│   └── __init__.py
│
├── sensitivity/                 # Risk scoring engine
│   ├── sensitivity_classifier.py # Per-entity + document-level risk
│   └── __init__.py
│
├── anonymization/               # Adaptive data masking
│   ├── masking.py               # MASK, TOKENIZE, REDACT engines
│   └── __init__.py
│
├── security/                    # Cryptographic protection
│   ├── aes_encryptor.py         # AES-256-GCM authenticated encryption
│   └── __init__.py
│
├── database/                    # Audit logging & persistence
│   ├── logger.py                # Audit log writer
│   ├── models.py                # Database models/schema
│   └── __init__.py
│
└── tests/                       # Test suite
    ├── test_pipeline.py         # End-to-end pipeline tests
    └── __init__.py
```

---

## 3. Component Deep-Dive

### 3.1 `pipeline.py` — The Orchestrator

The central nervous system of AdaptiShield. The `AdaptiShieldPipeline` class initializes all components and exposes three public methods:

- **`process_text(text, document_name)`** — Analyze raw text.
- **`process_file(file_path)`** — Parse and analyze a file (PDF/DOCX/CSV/TXT).
- **`process_bytes(content, filename)`** — Analyze uploaded file bytes (for API).

Internally, `_run_pipeline()` executes **6 sequential stages**:

| Stage | Component | What it does |
|-------|-----------|-------------|
| 1 | `TextCleaner` | Unicode normalization, whitespace cleanup |
| 2 | `RegexDetector` + `TransformerDetector` + `SpacyDetector` → `FusionEngine` | Hybrid PII detection with deduplication |
| 3 | `ContextValidator` + `ConfidenceEngine` | Semantic validation, co-occurrence boosts |
| 4 | `SensitivityClassifier` | Risk scoring (Σ weight × confidence) |
| 5 | `AdaptiveAnonymizer` | MASK / TOKENIZE / REDACT based on sensitivity |
| 6 | `AESEncryptor` | AES-256-GCM encryption of anonymized output |

The pipeline returns a comprehensive result dict containing: document metadata, detection stats per detector, risk analysis, anonymized entities, anonymized text, token map, encrypted payload, and processing time.

### 3.2 `demo.py` — CLI Demo

A command-line script using the `rich` library for pretty terminal output. Runs 3 pre-built test cases (Low Risk, KYC, Critical) through the pipeline and displays results in color-coded tables with risk badges.

### 3.3 `api/` — REST API (FastAPI)

#### `api/main.py`
The FastAPI application. Key endpoints:

| Method | Route | Auth | Purpose |
|--------|-------|------|---------|
| `GET` | `/` | None | Serves the custom web dashboard (`static/index.html`) |
| `GET` | `/health` | None | Health check |
| `POST` | `/auth/login` | None | JWT token generation |
| `POST` | `/analyze/text` | None* | Run pipeline on text input |
| `POST` | `/analyze/file` | None* | Run pipeline on uploaded file |
| `GET` | `/logs/recent` | None* | Fetch recent audit logs |
| `POST` | `/decrypt` | JWT (admin) | Decrypt an encrypted payload |

> *These endpoints originally required JWT authentication via `Depends(get_current_user)`. This was removed from the analysis and log endpoints to allow the custom dashboard to call them directly without token management. The `/decrypt` endpoint retains JWT auth since it exposes raw decrypted data.

The `_sanitize_result()` helper strips sensitive fields (`token_map`, `encryption_key`) from API responses.

#### `api/auth.py`
Handles JWT token lifecycle:
- `create_access_token()` — Signs a JWT with HS256.
- `verify_token()` — Validates and decodes a JWT.
- `hash_password()` / `verify_password()` — bcrypt-based password hashing.

### 3.4 `static/` — Custom Web Dashboard (NEW)

A fully client-side single-page application served by FastAPI's `StaticFiles` mount. Built with vanilla HTML, CSS, and JavaScript — no frameworks.

#### `static/index.html`
Multi-page SPA with 6 views:

| Page | Content |
|------|---------|
| **Overview** | Live metrics (docs processed, entities found, avg risk, avg latency), recent analyses list, entity-type bar chart, audit log |
| **Analyze** | Text input with 3 preloaded sample texts, risk banner (color-coded by level), full 10-step pipeline execution view with per-detector stats, entity table with confidence bars, anonymization map (original → transformed), side-by-side original vs anonymized text diff, compliance recommendations, AES-256 encryption details |
| **Pipeline** | Architecture diagram showing all 6 stages with descriptions; PII type grids for Indian-specific and Generic types, color-coded by sensitivity |
| **Entities** | Aggregated entity explorer across all analyses |
| **Anonymization** | Strategy policy table (sensitivity → strategy → example) + transformation history |
| **Audit Logs** | Full compliance audit trail |

#### `static/style.css`
Premium dark theme with:
- Glassmorphism cards (`backdrop-filter: blur`)
- Gradient accent buttons (blue-purple)
- Color-coded risk banners (green/yellow/red per level)
- Dynamic confidence bars (green >85%, yellow >60%, red below)
- Inter font from Google Fonts
- Smooth `fadeIn` animations
- Custom dark scrollbars

#### `static/app.js`
Client-side application logic:
- **State management** — Tracks all analyses, aggregated entities, totals.
- **Navigation** — Click-driven page switching via `data-page` attributes.
- **Health check** — Polls `/health` on load.
- **Analysis flow** — `fetch()` calls to `/analyze/text`, parses the response, and updates all UI components.
- **Sample loader** — 3 preloaded PII samples (Personal, KYC, Critical).
- **Live audit log** — Timestamped entries with color-coded severity dots.

### 3.5 `dashboard/app.py` — Streamlit Dashboard (Original)

A Streamlit application with 4 pages: Analyze Document, Analytics, Audit Logs, About. Uses Plotly for visualizations. This was the original dashboard before the custom web dashboard was created.

### 3.6 `configs/pii_config.py` — PII Definitions & Policies

The single source of truth for PII detection rules:

**Sensitivity Weights** (higher = more sensitive):
| Entity Type | Weight | Entity Type | Weight |
|------------|--------|------------|--------|
| PASSWORD | 100 | MEDICAL_RECORD | 95 |
| AADHAAR | 90 | PASSPORT | 85 |
| CREDIT_CARD | 80 | BANK_ACCOUNT | 75 |
| PAN | 60 | UPI_ID | 60 |
| PHONE | 30 | EMAIL | 20 |
| NAME | 10 | URL | 10 |

**Anonymization Policy** (maps sensitivity level to strategy):
| Level | Strategy | Example |
|-------|----------|---------|
| LOW | MASK | `r***@gmail.com` |
| MEDIUM | TOKENIZE | `PHONE_TOKEN_3F8A` |
| HIGH | REDACT | `[PAN_REDACTED]` |
| CRITICAL | REDACT | `[AADHAAR_REDACTED]` |

**Risk Levels** (based on cumulative document score):
| Level | Score Range |
|-------|------------|
| LOW | 0 – 30 |
| MEDIUM | 30 – 70 |
| HIGH | 70 – 150 |
| CRITICAL | 150+ |

**Regex Patterns**: Indian-specific (Aadhaar, PAN, Voter ID, Driving License, Passport, IFSC, UPI, GST, Pincode) and Generic (Email, Phone, IP, Credit Card, Bank Account, Date, URL, Password, Username).

### 3.7 `ingestion/` — Document Parsing

| File | Purpose |
|------|---------|
| `pdf_parser.py` | Extracts text from PDF files |
| `docx_parser.py` | Extracts text from Word documents |
| `csv_parser.py` | Extracts text from CSV/XLSX spreadsheets |
| `text_cleaner.py` | Unicode normalization, whitespace stripping, control character removal |

### 3.8 `detection/` — Hybrid PII Detection Engine

#### `regex_detector.py`
Compiles all patterns from `pii_config.py` and scans text. Each match is validated with entity-specific rules:
- **Aadhaar**: Must be exactly 12 digits → confidence 0.90
- **PAN**: Must match `[A-Z]{5}[0-9]{4}[A-Z]` → confidence 0.95
- **Credit Card**: Validated with the **Luhn algorithm** → confidence 0.95
- **Phone**: Must have ≥10 digits → confidence 0.88
- **IP Address**: Private IPs get lower confidence (0.60) vs public (0.75)

#### `transformer_detector.py`
Uses a pre-trained DeBERTa-v3 NER model for contextual PII detection. High recall — catches entities that regex misses based on semantic understanding.

#### `spacy_detector.py`
Uses spaCy's built-in Named Entity Recognition for entities like PERSON, ORG, GPE, LOC.

#### `fusion_engine.py`
The intelligence layer that merges detections from all three detectors:
1. Sorts all detections by text position.
2. Groups overlapping spans (using IoU ≥ 0.5 threshold).
3. For each group, selects the best entity type (priority: regex > transformer > spaCy).
4. **Confidence boosting**:
   - 1 detector agrees → unchanged
   - 2 detectors agree → confidence × 1.15
   - 3 detectors agree → confidence × 1.25 (capped at 1.0)

### 3.9 `context/` — Semantic Validation

#### `context_validator.py`
Examines an 80-character window around each detected entity:
- **Positive signals** (e.g., "email", "aadhaar", "password" near the entity) → confidence × 1.10
- **Negative signals** (e.g., "version", "order", "sku" near a phone number) → confidence × 0.65
- **Entity-specific rules**: Single-word names penalized (×0.75), bank accounts without financial context penalized (×0.40), DOB confirmed by birth-related keywords (×1.15)
- Entities with confidence < 0.45 are filtered out entirely.

#### `confidence_engine.py`
Final recalibration based on document-level signals:
- **Co-occurrence boosts**: If NAME + AADHAAR appear together, both get +0.10 boost. EMAIL + PASSWORD together get +0.15.
- **Frequency boost**: If the same entity type appears >3 times, confidence × 1.05.

### 3.10 `sensitivity/sensitivity_classifier.py` — Risk Scoring

For each entity: `effective_score = sensitivity_weight × confidence`

Entity-level classification:
| Effective Score | Sensitivity Level |
|----------------|-------------------|
| ≥ 70 | CRITICAL |
| ≥ 40 | HIGH |
| ≥ 20 | MEDIUM |
| < 20 | LOW |

Document-level: `risk_score = Σ (weight × confidence)` mapped to risk levels via the `RISK_LEVELS` config.

Also generates compliance **recommendations** (e.g., "Aadhaar detected — comply with UIDAI guidelines", "PASSWORDS DETECTED — Redact immediately").

### 3.11 `anonymization/masking.py` — Adaptive Anonymizer

Three engines, selected by the sensitivity level's policy:

| Engine | Strategy | Behavior |
|--------|----------|----------|
| `MaskingEngine` | MASK | Preserves structure: `j***@gmail.com`, `91****3210`, `R.....` |
| `TokenizationEngine` | TOKENIZE | Deterministic hash-based token: `PHONE_TOKEN_3F8A21BC` (reversible) |
| `RedactionEngine` | REDACT | Full replacement: `[AADHAAR_REDACTED]` (irreversible) |

`apply_to_text()` processes detections in **reverse position order** to preserve text offsets during replacement.

### 3.12 `security/aes_encryptor.py` — AES-256-GCM Encryption

- Generates a random 256-bit key (or derives one from a passphrase via PBKDF2).
- Each encryption uses a fresh 96-bit random nonce.
- Returns base64-encoded ciphertext + nonce.
- Provides authenticated encryption (confidentiality + integrity + authenticity).
- Supports `from_key_b64()` for key portability.

### 3.13 `database/` — Audit & Compliance

- **`logger.py`**: Writes an audit entry for every processed document — recording document ID, name, risk level, risk score, entity count, and timestamp.
- **`models.py`**: Defines the database schema/models for the audit trail.
- Designed for compliance with DPDP Act (India), PCI-DSS, HIPAA, and UIDAI guidelines.

### 3.14 `tests/test_pipeline.py`

End-to-end test suite covering:
- Regex detection accuracy (Aadhaar, PAN, Email, Phone, etc.)
- Context validation behavior
- Sensitivity classification thresholds
- Anonymization strategy application
- Full pipeline integration tests

---

## 4. Overall Data Flow

```
User Input (Text / PDF / DOCX / CSV)
        │
        ▼
┌─────────────────────────────────────────────────┐
│  Stage 1: INGESTION                             │
│  pdf_parser / docx_parser / csv_parser          │
│  → text_cleaner (Unicode norm, whitespace)      │
└─────────────────────┬───────────────────────────┘
                      │  cleaned UTF-8 text
                      ▼
┌─────────────────────────────────────────────────┐
│  Stage 2: DETECTION                             │
│  ┌──────────┐ ┌───────────────┐ ┌────────────┐ │
│  │  Regex   │ │  Transformer  │ │   spaCy    │ │
│  │ Detector │ │  (DeBERTa-v3) │ │  NER       │ │
│  └────┬─────┘ └──────┬────────┘ └─────┬──────┘ │
│       └──────────────┼────────────────┘         │
│                      ▼                          │
│            Fusion Engine                        │
│   (IoU dedup + confidence boosting)             │
└─────────────────────┬───────────────────────────┘
                      │  fused entity list
                      ▼
┌─────────────────────────────────────────────────┐
│  Stage 3: CONTEXT VALIDATION                    │
│  ContextValidator (±80 char window analysis)    │
│  → filter entities < 0.45 confidence            │
│  ConfidenceEngine (co-occurrence boosts)        │
└─────────────────────┬───────────────────────────┘
                      │  validated entities
                      ▼
┌─────────────────────────────────────────────────┐
│  Stage 4: SENSITIVITY & RISK                    │
│  SensitivityClassifier                          │
│  Per-entity: effective_score = weight × conf    │
│  Document:   risk_score = Σ effective_scores    │
│  → LOW / MEDIUM / HIGH / CRITICAL               │
└─────────────────────┬───────────────────────────┘
                      │  classified entities + risk level
                      ▼
┌─────────────────────────────────────────────────┐
│  Stage 5: ANONYMIZATION                         │
│  AdaptiveAnonymizer                             │
│  LOW→MASK  MEDIUM→TOKENIZE  HIGH/CRIT→REDACT   │
│  apply_to_text() (reverse-order replacement)    │
└─────────────────────┬───────────────────────────┘
                      │  anonymized text + entity map
                      ▼
┌─────────────────────────────────────────────────┐
│  Stage 6: ENCRYPTION                            │
│  AESEncryptor (AES-256-GCM)                     │
│  Fresh 96-bit nonce per encryption              │
│  → base64 ciphertext + nonce                    │
└─────────────────────┬───────────────────────────┘
                      │
                      ▼
              Audit Logger → Database
              API Response → Dashboard
```

---

## 5. Changes Made (Dashboard Overhaul)

### 5.1 `api/main.py` — Modifications

| Change | Before | After | Reason |
|--------|--------|-------|--------|
| Root route (`/`) | Returned JSON `{"status": "online"}` | Returns `FileResponse` serving `static/index.html` | Dashboard is now served from the API itself |
| Static files | Not configured | `app.mount("/static", StaticFiles(...))` added | Serves CSS, JS, and other static assets |
| Imports | Standard FastAPI only | Added `StaticFiles`, `FileResponse` | Required for serving the dashboard |
| `/analyze/text` | Required `Depends(get_current_user)` | No auth dependency | Allows the dashboard to call the API without JWT tokens |
| `/analyze/file` | Required `Depends(get_current_user)` | No auth dependency | Same reason — frictionless dashboard access |
| `/logs/recent` | Required `Depends(get_current_user)` | No auth dependency | Dashboard needs direct access to audit logs |
| `/decrypt` | Required JWT auth (admin role) | **Unchanged** — still requires JWT | Decryption exposes raw data; must remain protected |

### 5.2 `static/` — New Files Created

| File | Size | Purpose |
|------|------|---------|
| `index.html` | ~8KB | Multi-page SPA with 6 views (Overview, Analyze, Pipeline, Entities, Anonymization, Audit) |
| `style.css` | ~8KB | Dark glassmorphism theme with Inter font, gradient buttons, risk-color-coded banners, confidence bars, fade-in animations |
| `app.js` | ~8KB | Client-side state management, API calls, dynamic rendering of all dashboard components |

### 5.3 What Was NOT Changed

All backend pipeline logic remains **100% identical**:
- `pipeline.py` — No modifications
- `detection/` — All detectors untouched
- `context/` — Validators untouched
- `sensitivity/` — Classifier untouched
- `anonymization/` — Masking engines untouched
- `security/` — AES encryptor untouched
- `database/` — Logger untouched
- `configs/` — PII config untouched
- `auth.py` — JWT logic untouched (still used by `/decrypt`)
- `dashboard/app.py` — Streamlit dashboard untouched (still usable independently)

---

## 6. How to Run

```bash
# Start the API + Dashboard
cd adaptishield
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

# Open in browser
# Dashboard:  http://127.0.0.1:8000/
# Swagger UI: http://127.0.0.1:8000/docs

# CLI demo
python demo.py

# Streamlit dashboard (alternative)
streamlit run dashboard/app.py

# Run tests
python -m pytest tests/test_pipeline.py -v
```
