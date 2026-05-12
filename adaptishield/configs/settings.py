# AdaptiShield Configuration
# configs/settings.py

from pydantic import BaseSettings
from typing import Optional
import os

class Settings(BaseSettings):
    # App
    APP_NAME: str = "AdaptiShield"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://adaptishield:password@localhost:5432/adaptishield_db")

    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "adaptishield-secret-key-change-in-production")
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60
    AES_KEY: Optional[str] = os.getenv("AES_KEY")  # Auto-generated if not set

    # AI Models
    NER_MODEL: str = "dslim/bert-base-NER"           # Fast NER
    DEBERTA_MODEL: str = "microsoft/deberta-v3-base"  # High accuracy
    SPACY_MODEL: str = "en_core_web_lg"

    # Detection Thresholds
    REGEX_CONFIDENCE: float = 0.85
    NER_CONFIDENCE_THRESHOLD: float = 0.75
    FUSION_THRESHOLD: float = 0.70

    # Risk Levels
    LOW_RISK_THRESHOLD: float = 30.0
    MEDIUM_RISK_THRESHOLD: float = 70.0

    class Config:
        env_file = ".env"

settings = Settings()
