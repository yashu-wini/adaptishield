# database/models.py
"""
SQLAlchemy models for AdaptiShield audit logging and analytics.
"""

from sqlalchemy import Column, Integer, String, Float, DateTime, Text, JSON, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func

Base = declarative_base()


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    document_id = Column(String(64), nullable=False, index=True)
    document_name = Column(String(255))
    document_type = Column(String(32))  # pdf, docx, txt, csv
    user_id = Column(String(64))
    ip_address = Column(String(45))

    # Detection results
    entity_count = Column(Integer, default=0)
    entity_breakdown = Column(JSON)  # {"EMAIL": 2, "PHONE": 1, ...}
    risk_score = Column(Float)
    risk_level = Column(String(20))  # LOW / MEDIUM / HIGH / CRITICAL

    # Processing pipeline
    regex_count = Column(Integer, default=0)
    transformer_count = Column(Integer, default=0)
    spacy_count = Column(Integer, default=0)

    # Anonymization
    anonymization_applied = Column(Boolean, default=False)
    strategies_used = Column(JSON)  # ["MASK", "TOKENIZE", "REDACT"]

    # Output
    encrypted = Column(Boolean, default=False)
    processing_time_ms = Column(Float)

    # Raw results (optional, for compliance)
    full_report = Column(JSON)


class DetectedEntity(Base):
    __tablename__ = "detected_entities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    document_id = Column(String(64), index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    entity_type = Column(String(50))
    sensitivity_level = Column(String(20))
    confidence = Column(Float)
    anonymization_strategy = Column(String(20))
    detector_source = Column(String(50))


class APIUser(Base):
    __tablename__ = "api_users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(200), unique=True)
    hashed_password = Column(String(255))
    role = Column(String(20), default="analyst")  # admin, analyst, viewer
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True))
