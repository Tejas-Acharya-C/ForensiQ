"""Development database reset utility."""

import logging
import uuid
from pathlib import Path
from sqlalchemy import text
from app.core.config import get_settings
from app.database.session import SessionLocal, engine

logger = logging.getLogger("main")

DEV_USER_EMAIL = "dev@forensiq.local"
DEV_USER_PASSWORD = "Dev123!@#"


def ensure_dev_user():
    """Create the default dev user if no users exist in the database."""
    try:
        from app.models.user import User
        from app.core.security import hash_password

        with SessionLocal() as db:
            existing = db.query(User).first()
            if existing:
                return  # at least one user exists, nothing to do

            dev_user = User(
                id=uuid.uuid4(),
                email=DEV_USER_EMAIL,
                password_hash=hash_password(DEV_USER_PASSWORD),
                is_active=True,
            )
            db.add(dev_user)
            db.commit()
            logger.info(
                f"Dev user auto-created: email={DEV_USER_EMAIL}  password={DEV_USER_PASSWORD}"
            )
    except Exception as e:
        logger.warning(f"Could not auto-create dev user: {e}")


def reset_development_data():
    """
    Safely clears forensic data from the development database on startup.
    Preserves users, schema, and migrations.
    """
    settings = get_settings()

    # SAFETY 1: Strictly development environment only
    if settings.APP_ENV != "development":
        return

    # SAFETY 2: Strictly DEBUG mode only
    if not settings.DEBUG:
        return

    # SAFETY 3: Strictly SQLite only
    if not settings.DATABASE_URL.startswith("sqlite"):
        logger.warning(f"Development reset aborted: Configured database is not SQLite ({settings.DATABASE_URL.split('@')[-1] if '@' in settings.DATABASE_URL else settings.DATABASE_URL})")
        return

    # SAFETY 4: Exact file identity verification
    sqlite_path_str = settings.DATABASE_URL.replace("sqlite:///", "")
    if sqlite_path_str.startswith("./"):
        sqlite_path_str = sqlite_path_str[2:]
    
    # Resolve the intended local db file
    intended_db_path = (Path.cwd() / "forensiq.db").resolve()
    actual_db_path = Path(sqlite_path_str).resolve()
    
    if actual_db_path != intended_db_path:
        logger.warning(f"Development reset aborted: Database path {actual_db_path} does not match intended development database {intended_db_path}")
        return
        
    if not actual_db_path.exists():
        # Database hasn't been created yet, let migrations handle it normally
        return

    logger.info(f"Executing clean development restart against {actual_db_path}")
    
    with SessionLocal() as db:
        try:
            # SAFETY 5: Deletion in strict reverse-dependency order
            tables_to_clear = [
                "priority_results",
                "activity_evidence",
                "activity_findings",
                "finding_evidence",
                "relationships",
                "activities",
                "findings",
                "evidence",
                "evidence_sources",
                "investigations"
            ]
            
            for table in tables_to_clear:
                db.execute(text(f"DELETE FROM {table}"))
            
            db.commit()
            
            # SAFETY 6: Post-deletion explicit verification
            for table in tables_to_clear:
                result = db.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar()
                if result > 0:
                    raise RuntimeError(f"Table {table} still contains {result} rows after reset attempt. Possible orphaned records.")
                    
            logger.info("Development forensic data successfully cleared. Users and schema preserved.")

        except Exception as e:
            db.rollback()
            logger.error(f"Failed to reset development data: {e}")
            raise

    # Always ensure a dev user exists after reset
    ensure_dev_user()
