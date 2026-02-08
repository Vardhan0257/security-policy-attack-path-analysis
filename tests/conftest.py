"""
Pytest configuration and shared fixtures for all tests.
"""

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from unittest.mock import patch
import tempfile
import os

from src.api import app, get_db
from src.database import Base
import src.database
import src.api


@pytest.fixture(scope="function", autouse=True)
def setup_test_db():
    """
    Auto-use fixture that sets up test database for ALL tests.
    Creates a temporary file-based SQLite database and overrides both get_db
    dependency injection and SessionLocal for background tasks.
    Runs for each test function.
    """
    # Create a temporary file-based SQLite database
    temp_db_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.db')
    temp_db_path = temp_db_file.name
    temp_db_file.close()
    
    # Create SQLite engine
    test_engine = create_engine(
        f"sqlite:///{temp_db_path}",
        connect_args={"check_same_thread": False},
        echo=False
    )
    
    # Enable foreign keys for SQLite
    @event.listens_for(test_engine, "connect")
    def set_sqlite_pragma(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
    
    # Create all tables
    Base.metadata.create_all(bind=test_engine)
    
    # Create session factory bound to our test engine
    TestingSessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=test_engine
    )
    
    # Override get_db dependency to use test database
    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()
    
    # Override FastAPI dependency injection
    app.dependency_overrides[get_db] = override_get_db
    
    # Also patch SessionLocal in both database and api modules to use test session factory
    # This ensures background tasks and direct calls use the test database
    original_session_local = src.database.SessionLocal
    original_api_session_local = src.api.SessionLocal
    
    src.database.SessionLocal = TestingSessionLocal
    src.api.SessionLocal = TestingSessionLocal
    
    yield
    
    # Clean up: restore original SessionLocal
    src.database.SessionLocal = original_session_local
    src.api.SessionLocal = original_api_session_local
    
    # Remove dependency overrides
    app.dependency_overrides.clear()
    
    # Drop all tables and dispose engine
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()
    
    # Delete temp file
    try:
        os.unlink(temp_db_path)
    except:
        pass
