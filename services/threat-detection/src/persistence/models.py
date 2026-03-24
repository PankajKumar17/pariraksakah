"""SQLAlchemy ORM models for threat and event persistence."""

from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, Index, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
import os

Base = declarative_base()


class ThreatEvent(Base):
    """Persistent threat detection record."""
    __tablename__ = "threat_events"

    id = Column(String(64), primary_key=True, index=True)
    detected_at = Column(DateTime(timezone=True), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    
    # Network attributes
    src_ip = Column(String(45), index=True)
    dst_ip = Column(String(45), index=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(16), nullable=True)
    
    # User/behavioral attributes
    user_id = Column(String(128), index=True, nullable=True)
    hostname = Column(String(255), nullable=True)
    timestamp_user = Column(DateTime(timezone=True), nullable=True)
    
    # Detection attributes
    severity = Column(String(16), index=True)  # critical, high, medium, low
    threat_type = Column(String(64), index=True)  # port_scan, lateral_movement, c2_beacon, etc.
    confidence_score = Column(Float)  # 0.0-1.0
    
    # MITRE ATT&CK mapping
    mitre_technique = Column(String(16))  # e.g., T1071
    mitre_tactic = Column(String(32), index=True)  # e.g., command_and_control
    
    # Additional context
    description = Column(Text)
    payload_hash = Column(String(64), nullable=True)
    payload_entropy = Column(Float, nullable=True)
    bytes_transferred = Column(Integer, nullable=True)
    
    # Status tracking
    status = Column(String(32), default="open", index=True)  # open, investigating, resolved, false_positive
    analyst_note = Column(Text, nullable=True)
    
    __table_args__ = (
        Index("idx_threat_time_severity", "detected_at", "severity"),
        Index("idx_threat_src_dst", "src_ip", "dst_ip"),
        Index("idx_threat_user_time", "user_id", "detected_at"),
        Index("idx_threat_technique_tactic", "mitre_technique", "mitre_tactic"),
    )


class NetworkEvent(Base):
    """Raw network event for ingestion tracking."""
    __tablename__ = "network_events"

    id = Column(String(64), primary_key=True, index=True)
    ingested_at = Column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    event_time = Column(DateTime(timezone=True), nullable=False, index=True)
    
    # Network tuple
    src_ip = Column(String(45), index=True)
    dst_ip = Column(String(45), index=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(16), nullable=True)
    
    # Payload data
    payload_size = Column(Integer)
    payload_hash = Column(String(64), nullable=True)
    
    # Detection result (if any)
    threat_detected = Column(Boolean, default=False, index=True)
    threat_id = Column(String(64), nullable=True, index=True)
    threat_reason = Column(String(256), nullable=True)
    
    __table_args__ = (
        Index("idx_event_time_threat", "event_time", "threat_detected"),
        Index("idx_event_src_dst", "src_ip", "dst_ip"),
    )


class UEBAEvent(Base):
    """User and Entity Behavior Analytics event."""
    __tablename__ = "ueba_events"

    id = Column(String(64), primary_key=True, index=True)
    recorded_at = Column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    event_time = Column(DateTime(timezone=True), nullable=False, index=True)
    
    # User identity
    user_id = Column(String(128), index=True)
    hostname = Column(String(255), nullable=True)
    
    # Behavioral indicators
    failed_attempts = Column(Integer, default=0)
    privilege_escalation = Column(Boolean, default=False)
    off_hours = Column(Boolean, default=False)
    weekend = Column(Boolean, default=False)
    lateral_movement_score = Column(Float, default=0.0)
    
    # Anomaly detection
    anomaly_score = Column(Float, default=0.0)
    baseline_deviation = Column(Float, nullable=True)
    
    # Threat classification
    threat_detected = Column(Boolean, default=False, index=True)
    threat_id = Column(String(64), nullable=True, index=True)
    threat_reason = Column(String(256), nullable=True)
    
    description = Column(Text)
    
    __table_args__ = (
        Index("idx_ueba_user_time", "user_id", "event_time"),
        Index("idx_ueba_anomaly_threat", "anomaly_score", "threat_detected"),
    )


class AlertSuppression(Base):
    """Deduplication and suppression tracking for alert fatigue reduction."""
    __tablename__ = "alert_suppressions"

    id = Column(String(64), primary_key=True, index=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    
    # Threat reference
    threat_id = Column(String(64), index=True)
    threat_pattern_hash = Column(String(64), index=True)  # hash of threat signature
    
    # Suppression metadata
    reason = Column(String(256))  # "duplicate", "known_fp", "whitelisted", etc.
    suppression_until = Column(DateTime(timezone=True), index=True)
    count_suppressed = Column(Integer, default=1)
    
    __table_args__ = (
        Index("idx_suppression_pattern_time", "threat_pattern_hash", "suppression_until"),
    )


def get_db_url() -> str:
    """Build database connection string from environment variables."""
    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5432")
    db = os.getenv("POSTGRES_DB", "cybershield")
    user = os.getenv("POSTGRES_USER", "cybershield")
    password = os.getenv("POSTGRES_PASSWORD", "changeme_postgres")
    return f"postgresql://{user}:{password}@{host}:{port}/{db}"


def init_db_engine(db_url: str = None):
    """Initialize SQLAlchemy engine and create all tables."""
    if db_url is None:
        db_url = get_db_url()
    
    engine = create_engine(
        db_url,
        echo=False,
        pool_size=10,
        max_overflow=20,
    )
    
    # Create all tables
    Base.metadata.create_all(engine)
    
    return engine


def get_session_factory(engine):
    """Create SQLAlchemy session factory."""
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)
