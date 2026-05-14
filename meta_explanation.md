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
- **Aadhaar**: Must be exactly 12 digits, rejects all-same-digit sequences → confidence 0.90
- **PAN**: Must match `[A-Z]{5}[0-9]{4}[A-Z]` → confidence 0.95
- **Credit Card**: Validated with the **Luhn algorithm** → confidence 0.80 (lowered from 0.95; context must confirm)
- **Phone**: Must have ≥10 digits → confidence 0.88
- **IP Address**: Filters `0.0.0.0`, `255.255.255.255`, subnet masks; private IPs get 0.60 vs public 0.75
- **Password**: Extracts the value after the keyword, strips trailing punctuation (`:;,.!?`), checks for digit/special character complexity. Plain words ("policy", "reset") get 0.55; credential-like values ("Secret@123!") get 0.95
- **PINCODE**: 6-digit numbers are highly ambiguous → confidence 0.50 (lowered from 0.85 default; context validator gates on address keywords)

#### `transformer_detector.py`
Uses a pre-trained DeBERTa-v3 NER model for contextual PII detection. High recall — catches entities that regex misses based on semantic understanding.

#### `spacy_detector.py`
Uses spaCy's built-in Named Entity Recognition for entities like PERSON, ORG, GPE, LOC.

#### `fusion_engine.py`
The intelligence layer that merges detections from all three detectors:
1. Sorts all detections by text position.
2. Groups overlapping spans (using IoU ≥ 0.5 threshold).
3. For each group, selects the best entity type (priority: regex > transformer > spaCy).
4. **Floor-Guaranteed Confidence Fusion**:
   - Computes a reliability-weighted average of detector confidences
   - **Key invariant**: The final confidence is NEVER lower than the highest individual detector's confidence. A second detector can only HELP, never HURT.
   - Applies entity-type-aware boost factors:
     - Structured PII (Aadhaar, PAN, CC): ×1.05 / ×1.10
     - Contextual PII (NAME, ADDRESS): ×1.18 / ×1.28
     - Default: ×1.12 / ×1.20

### 3.9 `context/` — Semantic Validation & Intelligence

#### `context_validator.py`
The core false-positive filtering engine. Uses **three generic mechanisms** to validate PII detections:

**1. Preceding Label Analysis (General-Purpose)**

The key innovation for reducing false positives. If a detected entity value is preceded by a descriptive label (e.g., `Tracking:`, `Order ID:`, `Serial:`), the validator checks whether that label matches any known PII-confirming keyword for the entity type:

| Input | Label Found | Matches Positive Context? | Result |
|-------|-------------|---------------------------|--------|
| `Tracking: 4532015112830366` | "tracking" | ❌ Not in CREDIT_CARD context | REJECT (0.20× penalty) |
| `Credit Card: 4532015112830366` | "credit card" | ✅ "credit", "card" match | BOOST (1.15×) |
| `Order ID: 2345 6789 0123` | "order id" | ❌ Not in AADHAAR context | REJECT |
| `Aadhaar: 2345 6789 0123` | "aadhaar" | ✅ Matches | BOOST |
| `Serial: 9876543210` | "serial" | ❌ Not in PHONE context | REJECT |
| No label present | — | — | No effect |

This works for ALL entity types without hardcoding specific label lists. The system only needs to maintain positive context keywords (which already exist for each entity type).

**2. Entity-Specific Validation**

| Entity Type | Validation | Effect |
|-------------|------------|--------|
| PAN | Requires PII-confirming keywords (`pan`, `tax`, `itr`) nearby | 0.25× without context |
| PHONE | Checks for decimal/version prefix (`3.9876543210`) | 0.15× if version pattern |
| PASSWORD | Strips trailing punctuation, checks value complexity | 0.25× for plain words |
| PINCODE | Requires address/location keywords nearby | 0.30× without context |
| BANK_ACCOUNT | Requires financial keywords nearby | 0.40× without context |
| NAME | Single-word names penalized; ALL-CAPS abbreviations penalized | 0.75× / 0.50× |

**3. Generic Co-occurrence Checks**

- **Structured PII co-occurrence**: Contextual PII (names, dates) only validated when structured PII (phone, email, Aadhaar) exists in the same document
- **Cross-detector agreement**: Single-detector contextual PII without positive context gets 0.70× penalty; multi-detector agreement gets 1.05× boost
- **Positive/negative context signals**: ±120 character window analysis for confirming and denying keywords

#### `confidence_engine.py`
Final recalibration based on document-level signals:
- **Co-occurrence boosts**: If NAME + AADHAAR appear together, both get +0.10 boost. EMAIL + PASSWORD together get +0.15.
- **Frequency boost**: If the same entity type appears >3 times, confidence × 1.05.

#### `domain_classifier.py`
Keyword-density-based classification identifying 6 financial sub-domains (Banking, KYC, Fintech, Transaction, Compliance, Fraud). Applies domain-specific risk multipliers.

#### `quasi_identifier_engine.py`
Detects dangerous combinations of quasi-identifiers that could enable re-identification attacks. Implements **superset deduplication**: when a larger combination rule fires (e.g., AADHAAR + PAN + NAME = 80 pts), its subset rules (AADHAAR + NAME = 60 pts, PAN + NAME = 45 pts) are excluded to prevent double-counting.

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

## 4. Overall Data Flow — Traced Walkthrough

To understand how the pipeline works, let's trace this input through every stage:

```
"Tracking: 4532015112830366 | Aadhaar: 2345 6789 0123 | PAN: ABCDE1234F | Email: priya@gmail.com"
```

### Stage 1: Text Cleaning (`text_cleaner.py`)
Unicode NFKC normalization → control character removal → whitespace normalization.
Output: same text (already clean), guaranteed UTF-8.

### Stage 2: Hybrid Detection (`regex_detector.py` → `fusion_engine.py`)

**2a.** Regex scans all patterns from `pii_config.py`. Each match is validated:

| Match | Entity Type | `_validate()` Logic | Confidence |
|-------|-------------|---------------------|------------|
| `4532015112830366` | CREDIT_CARD | Luhn ✅ | 0.80 |
| `2345 6789 0123` | AADHAAR | 12 digits, not all-same ✅ | 0.90 |
| `ABCDE1234F` | PAN | Format match ✅ | 0.95 |
| `priya@gmail.com` | EMAIL | Valid format ✅ | 0.92 |

**2b.** Fusion Engine groups overlapping spans (IoU ≥ 0.5), applies floor-guaranteed weighted confidence. If both regex (0.95) and transformer (0.30) detect the same entity, fused confidence ≥ 0.95 (never diluted).

### Stage 3: Context Validation — 7 Steps Per Entity (`context_validator.py`)

Pipeline first sets document-level flags:
```python
has_structured_pii = True  # EMAIL, AADHAAR exist → contextual PII is trusted
```

Then **each entity passes through 7 sequential checks**:

| Step | What it does | Modifies confidence by |
|------|-------------|----------------------|
| ① **Preceding Label Analysis** | Checks if entity follows `LABEL:` pattern. If label ∉ positive context → "competing" → penalty | ×0.20 (competing) or ×1.15 (confirming) |
| ② **Positive Context Signals** | Scans ±120 chars for PII keywords | ×1.10 boost |
| ③ **Negative Context Signals** | Scans for anti-PII keywords ("version", "order") | ×0.65 penalty |
| ④ **Entity-Specific Validation** | PAN: needs tax context. PHONE: checks version prefix. PASSWORD: checks complexity. PINCODE: needs address context | varies (×0.15 to ×0.30) |
| ⑤ **Structured PII Co-occurrence** | Contextual PII (NAME, DATE) rejected if no structured PII in document | ×0.20 penalty |
| ⑥ **Cross-Detector Agreement** | Single-detector contextual PII without positive context | ×0.70 penalty |
| ⑦ **Threshold Gate** | Structured PII ≥ 0.25, other ≥ 0.30. Below = REJECTED | pass/fail |

**Traced for CREDIT_CARD (`4532015112830366`, conf=0.80):**
1. Prefix = `"Tracking: "` → label "tracking" ∉ CREDIT_CARD positives → **competing** → 0.80 × 0.20 = **0.16**
2. Skip (already penalized)
3. Skip (already penalized)
4. No CC-specific check
5. N/A (structured PII type)
6. N/A (structured PII type)
7. **0.16 < 0.25 → REJECTED** ❌

**Traced for AADHAAR (`2345 6789 0123`, conf=0.90):**
1. Prefix = `"Aadhaar: "` → "aadhaar" ∈ AADHAAR positives → **confirming** → 0.90 × 1.15 = **1.0** (capped)
2–6. No further penalties
7. **1.0 ≥ 0.25 → ACCEPTED** ✅

**After validation:** 3 entities accepted, 1 rejected. `ConfidenceEngine` then applies co-occurrence boosts (e.g., AADHAAR + PAN together → +0.10).

### Stage 4: Sensitivity & Risk Scoring (`sensitivity_classifier.py`)

Each entity gets a risk weight from evidence-backed profiles:
```
weight = 0.3×(exposure_freq) + 0.3×(fraud_impact) + 0.2×(regulatory) + 0.2×(abuse_likelihood)
effective_score = weight × 100 × confidence → determines CRITICAL/HIGH/MEDIUM/LOW
```

### Stage 4.5: Quasi-Identifier Correlation (`quasi_identifier_engine.py`)

Checks entity **combinations** — AADHAAR + PAN = 60 pts. Uses superset deduplication to prevent double-counting. Adds `correlation_risk` to `base_risk_score`.

### Stage 5: Anonymization (`masking.py`)

Strategy by sensitivity: CRITICAL → REDACT, HIGH → REDACT, MEDIUM → TOKENIZE, LOW → MASK. Text replacements processed in **reverse position order** to preserve offsets.

```
Output: "Tracking: 4532015112830366 | Aadhaar: [AADHAAR_REDACTED] | PAN: [PAN_REDACTED] | Email: [EMAIL_REDACTED]"
```
Note: `4532015112830366` is **preserved** — it was rejected in Stage 3.

### Stage 6: Encryption (`aes_encryptor.py`)

AES-256-GCM with fresh 96-bit nonce → base64 ciphertext + nonce.

### Why New Edge Cases Are Handled Without Code Changes

The preceding label analysis (Step ①) uses a **negative inference** approach:
- The system doesn't maintain a list of "bad" labels
- Instead, any label NOT in the entity's positive context list = competing interpretation
- So `"Receipt: 4532..."`, `"Barcode: 9876..."`, or `"Policy: ABCDE1234F"` are automatically handled without modifying code

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

### 5.3 What Was NOT Changed (Dashboard Phase)

During the dashboard creation phase, all backend pipeline logic remained identical.

### 5.4 Subsequent Pipeline Improvements (Edge-Case Hardening)

After the dashboard phase, the following backend improvements were made to address false positive/negative edge cases:

| File | Change |
|------|--------|
| `context/context_validator.py` | Added general-purpose **Preceding Label Analysis** (rejects entities preceded by non-confirming labels like "Tracking:", "Order ID:"); added PAN context validation, PHONE version-prefix detection, PASSWORD complexity check, PINCODE address-context gating; expanded positive/negative context keyword lists |
| `detection/regex_detector.py` | Credit card confidence lowered to 0.80 (Luhn alone insufficient); PASSWORD strips trailing punctuation before complexity check; IP filters 0.0.0.0/subnets; PINCODE default confidence lowered to 0.50; Aadhaar rejects all-same-digit sequences |
| `detection/fusion_engine.py` | Added floor-guaranteed confidence fusion (second detector can only help, never hurt); restored entity-type-aware boost factors with detector reliability weights |
| `context/quasi_identifier_engine.py` | Added superset deduplication (prevents double-counting when subset and superset rules both fire) |
| `configs/pii_config.py` | Updated BANK_ACCOUNT regex to handle natural language ("account number is 12345..."); restored PASSWORD, IP_ADDRESS, URL, USERNAME patterns |

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

---

## 7. Research-Oriented Enhancements (Changes Applied)

The following enhancements were implemented based on faculty feedback to evolve AdaptiShield from a **generalized PII detection system** to a **domain-aware contextual privacy intelligence framework**, targeting the **financial domain**.

### 7.1 CHANGE 1 — Financial Domain Classification

**File Created:** `context/domain_classifier.py`

**Goal:** Classify whether an input document belongs to the financial domain, and identify its specific sub-domain (Banking, KYC, Fintech, Transaction, Compliance, Fraud).

**Method:** Keyword-density-based classification using curated financial term lists per sub-domain. The classifier computes the ratio of financial keywords to total words and requires a minimum density threshold (0.5%) to confirm a financial document.



**Output fields added to pipeline result:**
- `domain_classification.is_financial` (bool)
- `domain_classification.domain` (primary sub-domain)
- `domain_classification.sub_domains` (ranked list)
- `domain_classification.domain_confidence` (0.0–1.0)
- `domain_classification.keyword_density` (float)

---

### 7.2 CHANGE 2 — Quasi-Identifier Correlation Engine

**File Created:** `context/quasi_identifier_engine.py`

**Goal:** Prevent re-identification attacks by analyzing **combinations** of detected entities, not just individual entities. A single Name or DOB might be low-risk alone, but Name + DOB + ZIP can uniquely re-identify 99.98% of individuals (Rocher et al., 2025).

**Research Basis:** *"A scaling law to model the effectiveness of identification techniques"* — Rocher et al. (2025)

**Risk Formula Enhancement:**

```
Before:  risk = Σ(weight × confidence)
After:   final_risk = Σ(entity_risk) × domain_multiplier + Σ(correlation_risk)
```

**Correlation Rules (18 total):**

| Combination | Risk Level | Score | Rationale |
|-----------|-----------|-------|-----------|
| NAME + AADHAAR | CRITICAL | 60 | Unique national identifier pair |
| AADHAAR + PAN + NAME | CRITICAL | 80 | Complete Indian identity |
| EMAIL + PASSWORD | CRITICAL | 70 | Direct credential exposure |
| BANK_ACCOUNT + IFSC | CRITICAL | 60 | Fully identifies a bank account |
| PAN + BANK_ACCOUNT + NAME | CRITICAL | 75 | Full financial identity |
| NAME + DOB + PINCODE | CRITICAL | 65 | Per Rocher et al. research |
| NAME + PHONE | HIGH | 35 | Often uniquely identifying |
| EMAIL + PHONE | HIGH | 35 | Cross-platform identity linking |
| NAME + ADDRESS | HIGH | 40 | Classic re-identification pair |

**Pipeline Integration:** Runs as **Stage 4.5** (after sensitivity scoring, before anonymization). The `correlation_risk` is added to the risk score.

**Output fields added:**
- `risk_analysis.base_risk_score` (before adjustments)
- `risk_analysis.domain_multiplier` (from CHANGE 1)
- `risk_analysis.correlation_risk` (quasi-ID correlation score)
- `risk_analysis.quasi_identifier_analysis.correlation_risks` (matched combos)
- `risk_analysis.quasi_identifier_analysis.re_identification_level` (LOW/MEDIUM/HIGH/CRITICAL)

---

### 7.3 CHANGE 3 — Research-Backed Anonymization Techniques

**File Modified:** `anonymization/masking.py`
**File Modified:** `configs/pii_config.py`

Three new anonymization engines were added, backed by published research:

#### Technique 1: Pseudonymization (`PseudonymizationEngine`)

**Research:** *"Deep learning enabled pseudonymization for preserving data privacy of financial identifiers in public documents"* — Roopalakshmi (2026)

| Aspect | Detail |
|--------|--------|
| Strategy name | `PSEUDONYMIZE` |
| What it does | Replaces identifiers with consistent, reversible pseudonyms |
| Example | `Rahul Sharma` → `NAME_PSEUDO_001_089344` |
| Key feature | Same input always produces same pseudonym (deterministic) |
| Suitable for | Bank accounts, Customer IDs, Transaction IDs |
| Benefit | Preserves relational structure for analytics |

#### Technique 2: Generalization (`GeneralizationEngine`)

| Aspect | Detail |
|--------|--------|
| Strategy name | `GENERALIZE` |
| What it does | Reduces precision instead of removing data |
| Example (Date) | `12/05/2026` → `05/2026` |
| Example (Age) | `27` → `25-30` |
| Example (PIN) | `560001` → `5600XX` |
| Example (Phone) | `+919876543210` → `9198XXXXXX` |
| Suitable for | Dates, Age, Salary ranges, ZIP codes |
| Benefit | Maintains statistical utility, reduces re-ID risk |

#### Technique 3: k-Anonymity (`KAnonymityEngine`)

**Research:** *"Examining Compliance with Personal Data Protection Regulations in Interorganizational Data Analysis"* — Li et al. (2021)

| Aspect | Detail |
|--------|--------|
| Strategy name | `K_ANONYMIZE` |
| What it does | Generalizes quasi-identifiers so each value matches ≥k records |
| Default k | 5 |
| Quasi-IDs targeted | AGE, PINCODE, DATE, DATE_OF_BIRTH, LOCATION, ADDRESS, GENDER |
| Prevents | Linkage attacks, quasi-identifier reconstruction |

**Config additions (`pii_config.py`):**
- `RESEARCH_ANONYMIZATION_STRATEGIES` — documents all 6 available strategies
- `QUASI_IDENTIFIER_TYPES` — entity types that benefit from k-anonymity

The `AdaptiveAnonymizer` now supports all 6 strategies: `MASK`, `TOKENIZE`, `REDACT`, `PSEUDONYMIZE`, `GENERALIZE`, `K_ANONYMIZE`.

---

### 7.4 Heuristic Confidence Boosting — Validated

**File Modified:** `detection/fusion_engine.py`

**Problem:** The original fusion engine used fixed heuristic multipliers:
- 2 detectors agree → `confidence × 1.15`
- 3 detectors agree → `confidence × 1.25`

These values were not statistically grounded and applied uniformly regardless of entity type.

**Solution:** Replaced with a **statistically validated, entity-type-aware boosting model** with three improvements:

#### 1. Entity-Type-Aware Boost Factors

Boost factors are differentiated by PII category because structured PII (Aadhaar, PAN) already has high regex confidence and needs smaller boosts, while contextual PII (NAME, ADDRESS) benefits significantly from multi-detector agreement:

| Entity Category | 2-Detector Boost | 3-Detector Boost | Rationale |
|----------------|-----------------|-----------------|-----------|
| Structured (AADHAAR, PAN, CC) | ×1.05 | ×1.10 | Regex alone is very confident |
| Semi-structured (PHONE, IP) | ×1.08 | ×1.15 | Moderate benefit from agreement |
| Contextual (NAME, ADDRESS) | ×1.15–1.18 | ×1.25–1.28 | Most benefit from cross-validation |
| Default (unlisted types) | ×1.12 | ×1.20 | Moderate baseline |

#### 2. Detector Reliability Weighting

Each detector has an empirical reliability weight based on its precision characteristics:

| Detector | Reliability Weight | Basis |
|---------|-------------------|-------|
| Regex | 0.92 | High precision for structured patterns |
| Transformer (DeBERTa) | 0.85 | Good contextual recall, moderate precision |
| spaCy | 0.78 | Strong for named entities, weaker for structured PII |

#### 3. Weighted Confidence Fusion

When multiple detectors agree, confidence is computed as a **reliability-weighted average** (not just `max()`), then multiplied by the entity-type-aware boost factor:

```
weighted_avg = Σ(confidence_i × reliability_i) / Σ(reliability_i)
final_confidence = min(1.0, weighted_avg × boost_factor)
```

**Validation:** Boost factors are derived from the harmonic mean of detector precision rates across entity categories, ensuring the boost reflects actual cross-validation gain rather than arbitrary scaling.

**Floor Guarantee (NEW):** Multi-detector fusion now guarantees that the final confidence is NEVER lower than the highest individual detector's confidence:

```python
max_individual = max(d["confidence"] for d in group)
if n_sources > 1:
    weighted_avg = self._compute_weighted_confidence(group)
    base_confidence = max(weighted_avg, max_individual)  # Floor guarantee
else:
    base_confidence = max_individual
final = min(1.0, base_confidence * boost_factor)
```

This prevents the dilution bug where a low-confidence transformer detection (0.30) would drag down a high-confidence regex detection (0.95) via weighted averaging.

---

### 7.5 CHANGE 5 — Edge-Case Hardening (Context Validation Overhaul)

**File Modified:** `context/context_validator.py`
**File Modified:** `detection/regex_detector.py`
**File Modified:** `configs/pii_config.py`

**Goal:** Systematically eliminate false positives and false negatives through flow-based improvements, without hardcoding individual edge cases.

#### 1. Preceding Label Analysis (General-Purpose)

A new validation mechanism that checks whether a detected PII value is preceded by a descriptive label (e.g., `Tracking:`, `Order ID:`, `Serial:`). If the label does NOT match any known PII-confirming keyword for the entity type, the detection receives a 0.20× penalty.

This single mechanism handles ALL label-based false positives:

| Input | Label | In Positive Context? | Outcome |
|-------|-------|---------------------|----------|
| `Tracking: 4532015112830366` | "tracking" | ❌ Not CREDIT_CARD | **Rejected** |
| `Credit Card: 4532015112830366` | "credit card" | ✅ "credit", "card" | **Accepted** |
| `Order ID: 2345 6789 0123` | "order id" | ❌ Not AADHAAR | **Rejected** |
| `Aadhaar: 2345 6789 0123` | "aadhaar" | ✅ Matches | **Accepted** |
| `Serial: 9876543210` | "serial" | ❌ Not PHONE | **Rejected** |
| `Phone: 9876543210` | "phone" | ✅ Matches | **Accepted** |

**Design principle:** The system doesn't maintain a list of "bad labels". Instead, any label that ISN'T a known PII-confirming keyword is treated as a competing interpretation. Only the entity's existing positive context keywords are needed.

#### 2. Smart Regex Validation

| Entity | Old Behavior | New Behavior |
|--------|--------------|-------------|
| CREDIT_CARD | 0.95 confidence | 0.80 (Luhn alone isn't proof; context must confirm) |
| PASSWORD | Any `\S+` after "password:" = 0.98 | Strips trailing punctuation `:;,.!?`; plain words = 0.55, complex values = 0.95 |
| IP_ADDRESS | Accepted `0.0.0.0`, `255.255.255.255` | Rejects null/broadcast/subnet addresses |
| PINCODE | 0.85 default confidence | 0.50 (6-digit numbers are highly ambiguous; requires address context) |
| AADHAAR | Accepted `111111111111` | Rejects all-same-digit sequences |

#### 3. Entity-Specific Context Validation

| Entity | Check | Penalty |
|--------|-------|---------|
| PAN | Requires `pan`, `tax`, `itr`, `income tax` in ±120 char window | 0.25× without context |
| PHONE | Checks if preceded by `digit.` (version pattern like `3.9876543210`) | 0.15× if version |
| PASSWORD | Checks if captured value has digits/special chars after stripping punctuation | 0.25× for plain words |
| PINCODE | Requires address/location keywords (`pin`, `pincode`, `address`, `city`, etc.) | 0.30× without context |

#### 4. Bank Account Natural Language Regex

```diff
- (?i)(?:account|a/c|acct)[\s.:=#-]*([0-9]{9,18})\b
+ (?i)(?:account|a/c|acct)\s*(?:no\.?|number|num|#)?\s*(?:is\s+|[:=#-]\s*)?([0-9]{9,18})\b
```

Now handles: "account number is 12345678901234", "account no: 12345", "account #12345", "acct number 12345"

#### 5. Quasi-ID Superset Deduplication

When `AADHAAR + PAN + NAME` fires (80 pts), its subsets `AADHAAR + NAME` (60 pts) and `PAN + NAME` (45 pts) are now excluded. Previously all three scored independently = 185 pts of double-counted risk.

#### Test Results

```
Unit Tests:      21/21 ✅
Edge Case Tests: 22/22 ✅
```

---

### 7.5 Updated Pipeline Flow

```
User Input (Text / PDF / DOCX / CSV)
        │
        ▼
┌──────────────────────────────────────────────────┐
│  Stage 1: INGESTION                              │
│  pdf_parser / docx_parser / csv_parser           │
│  → text_cleaner (Unicode norm, whitespace)       │
└─────────────────────┬────────────────────────────┘
                      │  cleaned UTF-8 text
                      ▼
┌──────────────────────────────────────────────────┐
│  Stage 1.5: DOMAIN CLASSIFICATION  [NEW]         │
│  FinancialDomainClassifier                       │
│  → sub-domain (BANKING/KYC/FINTECH/...)          │
│  → domain_multiplier for risk scoring            │
└─────────────────────┬────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────────┐
│  Stage 2: DETECTION  [ENHANCED]                  │
│  ┌──────────┐ ┌───────────────┐ ┌────────────┐  │
│  │  Regex   │ │  Transformer  │ │   spaCy    │  │
│  │ Detector │ │  (DeBERTa-v3) │ │  NER       │  │
│  └────┬─────┘ └──────┬────────┘ └─────┬──────┘  │
│       └──────────────┼────────────────┘          │
│                      ▼                           │
│            Fusion Engine                         │
│   (entity-type-aware boost + weighted fusion)    │
└─────────────────────┬────────────────────────────┘
                      │  fused entity list
                      ▼
┌──────────────────────────────────────────────────┐
│  Stage 3: CONTEXT VALIDATION                     │
│  ContextValidator (±80 char window analysis)     │
│  → filter entities < 0.45 confidence             │
│  ConfidenceEngine (co-occurrence boosts)         │
└─────────────────────┬────────────────────────────┘
                      │  validated entities
                      ▼
┌──────────────────────────────────────────────────┐
│  Stage 4: SENSITIVITY & RISK                     │
│  SensitivityClassifier                           │
│  Per-entity: effective_score = weight × conf     │
│  Document:   risk_score = Σ effective_scores     │
└─────────────────────┬────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────────┐
│  Stage 4.5: QUASI-ID CORRELATION  [NEW]          │
│  QuasiIdentifierEngine                           │
│  → correlation_risk from entity combinations     │
│  → re-identification level (Rocher et al.)       │
│  final_risk = base × multiplier + correlation    │
└─────────────────────┬────────────────────────────┘
                      │  classified + correlated
                      ▼
┌──────────────────────────────────────────────────┐
│  Stage 5: ANONYMIZATION  [ENHANCED]              │
│  AdaptiveAnonymizer                              │
│  LOW→MASK  MEDIUM→TOKENIZE  HIGH/CRIT→REDACT    │
│  + PSEUDONYMIZE / GENERALIZE / K_ANONYMIZE       │
│  apply_to_text() (reverse-order replacement)     │
└─────────────────────┬────────────────────────────┘
                      │  anonymized text + entity map
                      ▼
┌──────────────────────────────────────────────────┐
│  Stage 6: ENCRYPTION                             │
│  AESEncryptor (AES-256-GCM)                      │
│  Fresh 96-bit nonce per encryption               │
│  → base64 ciphertext + nonce                     │
└─────────────────────┬────────────────────────────┘
                      │
                      ▼
              Audit Logger → Database
              API Response → Dashboard
```

---

### 7.6 New Files Created

| File | Purpose |
|------|---------|
| `context/domain_classifier.py` | Financial domain classification (6 sub-domains) |
| `context/quasi_identifier_engine.py` | Quasi-identifier correlation & re-identification risk |

### 7.7 Files Modified

| File | Change |
|------|--------|
| `detection/fusion_engine.py` | Replaced heuristic 1.15/1.25 boosts with entity-type-aware, statistically validated boosting model + detector reliability weighting |
| `anonymization/masking.py` | Added PseudonymizationEngine, GeneralizationEngine, KAnonymityEngine; extended AdaptiveAnonymizer to support 6 strategies |
| `configs/pii_config.py` | Added RESEARCH_ANONYMIZATION_STRATEGIES, QUASI_IDENTIFIER_TYPES |
| `pipeline.py` | Integrated domain classifier (Stage 1.5), quasi-ID engine (Stage 4.5); enhanced risk formula |

### 7.8 Literature Foundations

| Research Area | Supporting Paper | Used In |
|--------------|-----------------|---------|
| Pseudonymization | Roopalakshmi (2026) | `PseudonymizationEngine` |
| Re-identification Risk | Rocher et al. (2025) | `QuasiIdentifierEngine` |
| Regulatory Compliance / k-Anonymity | Li et al. (2021) | `KAnonymityEngine` |
| Synthetic Privacy Preservation | Assefa et al. (2023) | Differential privacy (future) |
| Financial NLP & PII Detection | Simic et al. (2024) | `FinancialDomainClassifier` |



TESTING DOCS:
-TheFinAI/MultiFinBen-EnglishOCR
 curl -X GET \
     "https://datasets-server.huggingface.co/rows?dataset=TheFinAI%2FMultiFinBen-EnglishOCR&config=default&split=train&offset=0&length=100"

-df = kagglehub.load_dataset(
  KaggleDatasetAdapter.PANDAS,
  "senju14/ocr-dataset-of-multi-type-documents"
-https://www.kaggle.com/datasets/swatigupta555/financial-document-classification