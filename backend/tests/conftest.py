import os
import shutil
import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# ── Create isolated temporary test directory outside the source tree ──
_TEST_TEMP_DIR = Path(tempfile.mkdtemp(prefix="forensiq_test_")).resolve()
TEST_DB_FILE = _TEST_TEMP_DIR / "test_forensiq.db"
TEST_STAGING_DIR = _TEST_TEMP_DIR / "staging"
TEST_SOURCES_DIR = _TEST_TEMP_DIR / "sources"

TEST_STAGING_DIR.mkdir(parents=True, exist_ok=True)
TEST_SOURCES_DIR.mkdir(parents=True, exist_ok=True)

# Strict isolation guarantees — verify no overlap with any repository or production path
LIVE_DB_FILE = (Path.cwd() / "forensiq.db").resolve()
TRIAL_DB_FILE = (Path.cwd() / "data" / "trial" / "forensiq_trial.db").resolve()
PROD_STAGING_DIR = (Path.cwd() / "data" / "staging").resolve()
PROD_SOURCES_DIR = (Path.cwd() / "data" / "sources").resolve()

assert TEST_DB_FILE != LIVE_DB_FILE, "FATAL: Test DB overlaps live forensiq.db!"
assert TEST_DB_FILE != TRIAL_DB_FILE, "FATAL: Test DB overlaps trial forensiq_trial.db!"
assert TEST_STAGING_DIR != PROD_STAGING_DIR, "FATAL: Test staging overlaps production staging!"
assert TEST_SOURCES_DIR != PROD_SOURCES_DIR, "FATAL: Test sources overlaps production sources!"

posix_db_path = TEST_DB_FILE.as_posix()
if not posix_db_path.startswith("/"):
    posix_db_path = f"/{posix_db_path}"

os.environ["DATABASE_URL"] = f"sqlite://{posix_db_path}"
os.environ["UPLOAD_STAGING_DIR"] = str(TEST_STAGING_DIR)
os.environ["UPLOAD_SOURCE_DIR"] = str(TEST_SOURCES_DIR)
os.environ["APP_ENV"] = "testing"

from app.core.config import get_settings
get_settings.cache_clear()

from app.main import create_app
from app.database.session import get_db, create_db_engine, SessionLocal
from app.database.base import Base


@pytest.fixture(scope="session", autouse=True)
def isolated_test_suite_environment():
    """Session-level fixture managing isolated test resources and teardown cleanup."""
    yield
    # Teardown: Clean up dedicated isolated temporary test directory
    get_settings.cache_clear()
    shutil.rmtree(_TEST_TEMP_DIR, ignore_errors=True)


@pytest.fixture(scope="session")
def app_client():
    engine = create_db_engine()
    Base.metadata.create_all(bind=engine)
    app = create_app()
    client = TestClient(app)
    return client


@pytest.fixture(scope="session")
def db_session():
    db = SessionLocal()
    yield db
    db.close()
