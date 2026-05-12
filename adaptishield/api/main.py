# api/main.py
"""
AdaptiShield FastAPI Application
Secure REST API with JWT authentication.
"""

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional
import sys, os

from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from api.auth import create_access_token, verify_token, hash_password, verify_password
from pipeline import AdaptiShieldPipeline

app = FastAPI(
    title="AdaptiShield API",
    description="Context-Aware Privacy Intelligence Framework",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files directory
os.makedirs(os.path.join(os.path.dirname(__file__), "../static"), exist_ok=True)
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "../static")), name="static")

security = HTTPBearer()

# Initialize pipeline (lazy - transformer loads on first use)
pipeline = AdaptiShieldPipeline(use_transformer=True, use_spacy=True)

# ─── Mock user store (replace with DB in production) ────────────
USERS = {
    "admin": hash_password("admin123"),
    "analyst": hash_password("analyst123"),
}

# ─── Auth Models ────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str

class TextAnalysisRequest(BaseModel):
    text: str
    document_name: Optional[str] = "api_text_input"
    encrypt_output: Optional[bool] = True


# ─── Dependency: Verify JWT ──────────────────────────────────────
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return payload


# ─── Routes ─────────────────────────────────────────────────────

@app.get("/", tags=["Health"])
def root():
    return FileResponse(os.path.join(os.path.dirname(__file__), "../static/index.html"))

@app.get("/health", tags=["Health"])
def health():
    return {"status": "healthy", "pipeline": "ready"}


@app.post("/auth/login", tags=["Authentication"])
def login(request: LoginRequest):
    """Authenticate and receive a JWT token."""
    hashed = USERS.get(request.username)
    if not hashed or not verify_password(request.password, hashed):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": request.username, "role": "analyst"})
    return {"access_token": token, "token_type": "bearer"}


@app.post("/analyze/text", tags=["Analysis"])
def analyze_text(request: TextAnalysisRequest):
    """
    Analyze plain text for PII.
    Returns detected entities, risk score, anonymized text, and encrypted payload.
    """
    if not request.text.strip():
        raise HTTPException(status_code=400, detail="Text cannot be empty")
    try:
        result = pipeline.process_text(request.text, document_name=request.document_name)
        return _sanitize_result(result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pipeline error: {str(e)}")


@app.post("/analyze/file", tags=["Analysis"])
async def analyze_file(file: UploadFile = File(...)):
    """
    Upload and analyze a document (PDF, DOCX, TXT, CSV).
    Returns full pipeline analysis.
    """
    allowed_types = [".pdf", ".docx", ".txt", ".csv", ".xlsx"]
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {ext}. Allowed: {allowed_types}"
        )

    try:
        content = await file.read()
        result = pipeline.process_bytes(content, filename=file.filename)
        return _sanitize_result(result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File processing error: {str(e)}")


@app.get("/logs/recent", tags=["Audit"])
def get_recent_logs(limit: int = 20):
    """Retrieve recent audit logs."""
    try:
        logs = pipeline.audit_logger.get_recent_logs(limit=limit) if pipeline.audit_logger else []
        return {"logs": logs, "count": len(logs)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/decrypt", tags=["Security"])
def decrypt_payload(
    payload: dict,
    current_user: dict = Depends(get_current_user)
):
    """Decrypt an encrypted payload (authorized access only)."""
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Decryption requires admin role")
    try:
        from security.aes_encryptor import AESEncryptor
        key_b64 = payload.get("encryption_key")
        if not key_b64:
            raise HTTPException(status_code=400, detail="encryption_key required")
        encryptor = AESEncryptor.from_key_b64(key_b64)
        decrypted = encryptor.decrypt(payload["encrypted_payload"])
        return {"decrypted_text": decrypted}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")


def _sanitize_result(result: dict) -> dict:
    """Remove sensitive raw values from API response."""
    sanitized = result.copy()
    # Don't expose token map over API (security risk)
    sanitized.pop("token_map", None)
    # Don't expose encryption key in analysis response
    sanitized.pop("encryption_key", None)
    return sanitized


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
