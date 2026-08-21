#!/usr/bin/env python3
"""
ForensiQ — First User Bootstrap Script
=======================================
Creates the first investigator account on a fresh database.

Usage:
    python scripts/create_first_user.py

Rules:
    - If any user already exists, the script exits without creating another.
    - Password is hashed using the application's standard bcrypt implementation.
    - Credentials are never hardcoded or printed.
    - Must be run explicitly by the operator — never called automatically at startup.
"""

import os
import sys
import getpass
import re

# Ensure the backend package is importable from the project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

# Load .env before importing settings (mirrors application startup)
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))
except ImportError:
    pass  # python-dotenv not installed; rely on environment variables directly


def validate_email(email: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email.strip()))


def validate_password(password: str) -> list[str]:
    errors = []
    if len(password) < 8:
        errors.append("Password must be at least 8 characters.")
    return errors


def main() -> int:
    print()
    print("=" * 56)
    print("  ForensiQ — First User Bootstrap")
    print("=" * 56)
    print()

    # Import application components after path setup
    try:
        from app.core.config import get_settings
        from app.core.security import hash_password
        from app.database.session import create_db_engine, SessionLocal
        from app.database.base import Base
        from app.models.user import User
        import uuid
    except Exception as exc:
        print(f"[ERROR] Failed to import application modules: {exc}")
        print("        Ensure you are running from the project root directory")
        print("        and that dependencies are installed (pip install -r requirements.txt).")
        return 1

    # Connect to database
    try:
        settings = get_settings()
        engine = create_db_engine()
        # Ensure tables exist (safe no-op if already created by migrations)
        Base.metadata.create_all(bind=engine)
        db = SessionLocal()
    except Exception as exc:
        print(f"[ERROR] Cannot connect to database: {exc}")
        print(f"        DATABASE_URL = {settings.DATABASE_URL.split('@')[-1] if '@' in settings.DATABASE_URL else settings.DATABASE_URL}")
        return 1

    try:
        # Check whether any user already exists
        existing_count = db.query(User).count()
        if existing_count > 0:
            print(f"[INFO]  {existing_count} user(s) already exist in the database.")
            print("        No action taken. Use the application login to authenticate.")
            print()
            return 0

        print("  No users found. Creating the first investigator account.")
        print()

        # Collect email
        while True:
            email = input("  Email address: ").strip()
            if not email:
                print("  [!] Email cannot be empty.")
                continue
            if not validate_email(email):
                print("  [!] Invalid email address format. Please try again.")
                continue
            # Check for duplicate (defensive — already confirmed count is 0, but guard anyway)
            if db.query(User).filter(User.email == email.lower()).first():
                print(f"  [!] Email '{email}' is already registered.")
                continue
            break

        # Collect password
        while True:
            password = getpass.getpass("  Password (min 8 characters): ")
            errors = validate_password(password)
            if errors:
                for err in errors:
                    print(f"  [!] {err}")
                continue
            confirm = getpass.getpass("  Confirm password: ")
            if password != confirm:
                print("  [!] Passwords do not match. Please try again.")
                continue
            break

        # Create user
        user = User(
            id=uuid.uuid4(),
            email=email.lower(),
            password_hash=hash_password(password),
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        # Clear password from memory immediately
        del password
        del confirm

        print()
        print(f"  [OK]  First user created successfully.")
        print(f"        Email:   {user.email}")
        print(f"        User ID: {user.id}")
        print()
        print("  You can now log in to ForensiQ.")
        print()
        return 0

    except KeyboardInterrupt:
        print()
        print()
        print("  [CANCELLED] No user was created.")
        print()
        db.rollback()
        return 1
    except Exception as exc:
        db.rollback()
        print(f"[ERROR] Failed to create user: {exc}")
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
