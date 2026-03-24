"""Database initialization and management utilities."""

import logging
import time
from contextlib import contextmanager
from sqlalchemy import text
from sqlalchemy.orm import Session
from .models import init_db_engine, get_session_factory

logger = logging.getLogger("threat-detection.db")

_engine = None
_session_factory = None


def init_database(db_url: str = None, max_retries: int = 5, retry_delay: int = 2) -> bool:
    """Initialize database connection and create schema."""
    global _engine, _session_factory
    
    for attempt in range(max_retries):
        try:
            logger.info(f"Attempting database initialization (attempt {attempt + 1}/{max_retries})...")
            
            _engine = init_db_engine(db_url)
            _session_factory = get_session_factory(_engine)
            
            # Test connection
            with get_session() as session:
                session.execute(text("SELECT 1"))
            
            logger.info("✅ Database initialized successfully")
            return True
            
        except Exception as e:
            logger.warning(f"Database initialization failed: {e}")
            if attempt < max_retries - 1:
                logger.info(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                logger.error(f"Database initialization failed after {max_retries} attempts")
                return False
    
    return False


def get_engine():
    """Get SQLAlchemy engine."""
    if _engine is None:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    return _engine


def get_session() -> Session:
    """Get a database session for use in context manager."""
    if _session_factory is None:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    return _session_factory()


@contextmanager
def session_scope():
    """Provide a transactional scope around a series of operations."""
    session = get_session()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def close_database():
    """Close database connections."""
    global _engine
    if _engine:
        _engine.dispose()
        logger.info("Database connections closed")


def get_db_health() -> dict:
    """Check database health."""
    try:
        with get_session() as session:
            session.execute(text("SELECT 1"))
        return {"status": "healthy", "error": None}
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return {"status": "unhealthy", "error": str(e)}


def apply_retention_policies(retention_days: int = 30) -> dict:
    """Delete stale records using a simple retention policy.

    This keeps history bounded even without external schedulers.
    """
    if retention_days <= 0:
        return {"retention_days": retention_days, "deleted": {}}

    deleted = {}
    with session_scope() as session:
        deleted["threat_events"] = session.execute(
            text("DELETE FROM threat_events WHERE detected_at < NOW() - (:days || ' days')::INTERVAL"),
            {"days": retention_days},
        ).rowcount
        deleted["network_events"] = session.execute(
            text("DELETE FROM network_events WHERE event_time < NOW() - (:days || ' days')::INTERVAL"),
            {"days": retention_days},
        ).rowcount
        deleted["ueba_events"] = session.execute(
            text("DELETE FROM ueba_events WHERE event_time < NOW() - (:days || ' days')::INTERVAL"),
            {"days": retention_days},
        ).rowcount
        session.commit()

    return {"retention_days": retention_days, "deleted": deleted}
