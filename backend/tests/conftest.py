import os
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

# Force test database BEFORE importing app modules
os.environ["DATABASE_URL"] = "sqlite:///./test_forensiq.db"

# Remove old test db if it exists
if os.path.exists("test_forensiq.db"):
    os.remove("test_forensiq.db")

from app.main import create_app
from app.database.session import get_db, create_db_engine, SessionLocal
from app.database.base import Base
from app.models.user import User
from app.core.security import hash_password, create_access_token

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

@pytest.fixture(scope="session")
def auth_headers(db_session: Session):
    email = "investigator@company.test"
    user = db_session.query(User).filter_by(email=email).first()
    if not user:
        user = User(
            id=uuid.uuid4(),
            email=email,
            password_hash=hash_password("Investigator123!"),
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

    token = create_access_token(user_id=user.id, email=user.email)
    return {"Authorization": f"Bearer {token}"}
