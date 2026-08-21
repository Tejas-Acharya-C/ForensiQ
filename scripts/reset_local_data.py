#!/usr/bin/env python3
"""
ForensiQ — Local Development Data Reset Utility
================================================
WARNING: This permanently removes local ForensiQ data.

This script is for LOCAL DEVELOPMENT only.
NEVER run this against a production database.

What it does:
    1. Confirms the configured database is a local SQLite file (refuses PostgreSQL).
    2. Asks for explicit typed confirmation before proceeding.
    3. Removes the SQLite database file.
    4. Clears the data/sources/ and data/staging/ directories.
    5. Recreates the empty schema using Alembic migrations.

After running, start ForensiQ on a clean empty database.
Then create the first user: python scripts/create_first_user.py

Usage:
    python scripts/reset_local_data.py
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

# Ensure the backend package is importable from the project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))
except ImportError:
    pass

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_SOURCES_DIR = PROJECT_ROOT / "data" / "sources"
DATA_STAGING_DIR = PROJECT_ROOT / "data" / "staging"
ALEMBIC_INI = PROJECT_ROOT / "alembic.ini"


def main() -> int:
    print()
    print("=" * 56)
    print("  ForensiQ — Local Development Data Reset")
    print("=" * 56)
    print()
    print("  !!!  WARNING  !!!")
    print("  This permanently removes local ForensiQ data.")
    print("  This is for LOCAL DEVELOPMENT only.")
    print()

    # Import settings to detect database type
    try:
        from app.core.config import get_settings
        settings = get_settings()
        db_url = settings.DATABASE_URL
    except Exception as exc:
        print(f"[ERROR] Cannot load application settings: {exc}")
        return 1

    # Safety: refuse to run on PostgreSQL/production databases
    if not db_url.startswith("sqlite"):
        print(f"[REFUSED] DATABASE_URL does not point to a local SQLite database.")
        print(f"          Configured: {db_url.split('@')[-1] if '@' in db_url else db_url}")
        print()
        print("          This script only operates on local SQLite databases.")
        print("          For PostgreSQL/production resets, use your database admin tools.")
        print()
        return 1

    # Identify the SQLite file path
    # sqlite:///./forensiq.db  →  PROJECT_ROOT/forensiq.db
    sqlite_path_str = db_url.replace("sqlite:///", "")
    if sqlite_path_str.startswith("./"):
        sqlite_path_str = sqlite_path_str[2:]
    sqlite_file = PROJECT_ROOT / sqlite_path_str

    print("  The following will be permanently deleted:")
    print(f"    Database:      {sqlite_file}")
    print(f"    Sources dir:   {DATA_SOURCES_DIR}")
    print(f"    Staging dir:   {DATA_STAGING_DIR}")
    print()

    # Require typed confirmation
    confirmation = input('  Type "RESET" to confirm, or press Enter to cancel: ').strip()
    if confirmation != "RESET":
        print()
        print("  [CANCELLED] No data was removed.")
        print()
        return 0

    print()

    # Step 1: Remove SQLite database file
    if sqlite_file.exists():
        try:
            sqlite_file.unlink()
            print(f"  [OK]  Removed database: {sqlite_file.name}")
        except Exception as exc:
            print(f"  [ERROR] Could not remove database file: {exc}")
            return 1
    else:
        print(f"  [SKIP] Database file not found (already clean): {sqlite_file.name}")

    # Step 2: Clear data/sources/ directory contents
    if DATA_SOURCES_DIR.exists():
        removed_sources = 0
        for item in DATA_SOURCES_DIR.iterdir():
            try:
                if item.is_dir():
                    shutil.rmtree(item)
                else:
                    item.unlink()
                removed_sources += 1
            except Exception as exc:
                print(f"  [WARN] Could not remove {item}: {exc}")
        print(f"  [OK]  Cleared data/sources/ ({removed_sources} items removed)")
    else:
        DATA_SOURCES_DIR.mkdir(parents=True, exist_ok=True)
        print("  [OK]  Created data/sources/ (was missing)")

    # Step 3: Clear data/staging/ directory contents
    if DATA_STAGING_DIR.exists():
        removed_staging = 0
        for item in DATA_STAGING_DIR.iterdir():
            try:
                if item.is_dir():
                    shutil.rmtree(item)
                else:
                    item.unlink()
                removed_staging += 1
            except Exception as exc:
                print(f"  [WARN] Could not remove {item}: {exc}")
        print(f"  [OK]  Cleared data/staging/ ({removed_staging} items removed)")
    else:
        DATA_STAGING_DIR.mkdir(parents=True, exist_ok=True)
        print("  [OK]  Created data/staging/ (was missing)")

    # Step 4: Recreate schema via Alembic
    print()
    print("  Running Alembic migrations to recreate empty schema...")
    print()
    if not ALEMBIC_INI.exists():
        print(f"  [ERROR] alembic.ini not found at {ALEMBIC_INI}")
        print("          Run Alembic manually: alembic -c alembic.ini upgrade head")
        return 1

    try:
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "-c", str(ALEMBIC_INI), "upgrade", "head"],
            cwd=str(PROJECT_ROOT),
            capture_output=False,
        )
        if result.returncode != 0:
            print()
            print("  [ERROR] Alembic migration failed. Check the output above.")
            return 1
    except Exception as exc:
        print(f"  [ERROR] Could not run Alembic: {exc}")
        return 1

    print()
    print("  [OK]  ForensiQ local data reset complete.")
    print()
    print("  Next steps:")
    print("    1. Create the first user:  python scripts/create_first_user.py")
    print("    2. Start the application:  uvicorn app.main:app --app-dir backend --reload")
    print("    3. Log in and create a case.")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
