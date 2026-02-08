#!/usr/bin/env python
"""
Database initialization script.

Creates all tables and populates initial data.

Usage:
    python scripts/init_db.py
"""

import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.database import init_db, SessionLocal, ServiceAccount
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main():
    """Initialize database."""
    logger.info("Initializing database...")
    
    # Create tables
    init_db()
    
    # Add default service accounts (optional)
    db = SessionLocal()
    try:
        # Check if any accounts exist
        existing = db.query(ServiceAccount).first()
        if existing:
            logger.info("Service accounts already exist, skipping defaults")
        else:
            logger.info("Creating default service accounts...")
            
            accounts = [
                ServiceAccount(
                    name="local-environment",
                    provider="generic",
                    source_type="local"
                ),
                ServiceAccount(
                    name="aws-production",
                    provider="aws",
                    source_type="arn"
                ),
                ServiceAccount(
                    name="azure-production",
                    provider="azure",
                    source_type="managed_identity"
                ),
            ]
            
            for account in accounts:
                db.add(account)
            
            db.commit()
            logger.info(f"Created {len(accounts)} default service accounts")
    
    finally:
        db.close()
    
    logger.info("Database initialization complete!")
    print("\nNext steps:")
    print("1. Update .env with DATABASE_URL if using non-default PostgreSQL")
    print("2. Run: uvicorn src.api:app --reload")
    print("3. Visit http://localhost:8000/docs for API documentation")


if __name__ == "__main__":
    main()
