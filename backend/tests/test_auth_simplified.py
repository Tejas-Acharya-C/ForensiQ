"""Tests for simplified authentication and access control model (Phase S2)."""

import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import create_app
from app.database.session import get_db, create_db_engine, SessionLocal
from app.database.base import Base
from app.models.user import User
from app.models.investigation import Investigation
from app.core.security import hash_password, create_access_token


@pytest.fixture(scope="module")
def app_client():
    engine = create_db_engine()
    Base.metadata.create_all(bind=engine)
    app = create_app()
    client = TestClient(app)
    return client


@pytest.fixture(scope="module")
def db_session():
    db = SessionLocal()
    yield db
    db.close()


@pytest.fixture
def auth_headers(db_session: Session):
    # Ensure standard investigator user exists
    user = db_session.query(User).filter_by(email="investigator@company.test").first()
    if not user:
        user = User(
            id=uuid.uuid4(),
            email="investigator@company.test",
            password_hash=hash_password("Investigator123!"),
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

    token = create_access_token(user_id=user.id, email=user.email)
    return {"Authorization": f"Bearer {token}"}


def test_login_success(app_client: TestClient, db_session: Session):
    email = "login_test@company.test"
    user = db_session.query(User).filter_by(email=email).first()
    if not user:
        user = User(
            id=uuid.uuid4(),
            email=email,
            password_hash=hash_password("ValidPassword123!"),
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()

    response = app_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "ValidPassword123!"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["email"] == email


def test_login_invalid_credentials(app_client: TestClient):
    response = app_client.post(
        "/api/v1/auth/login",
        json={"email": "nonexistent@company.test", "password": "WrongPassword!"},
    )
    assert response.status_code == 401


def test_unauthenticated_request_rejected(app_client: TestClient):
    response = app_client.get("/api/v1/investigations")
    assert response.status_code == 401


def test_authenticated_user_access(app_client: TestClient, auth_headers: dict):
    # Authenticated user can fetch their profile
    me_resp = app_client.get("/api/v1/auth/me", headers=auth_headers)
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == "investigator@company.test"

    # Authenticated user can list investigations
    inv_resp = app_client.get("/api/v1/investigations", headers=auth_headers)
    assert inv_resp.status_code == 200
    assert "items" in inv_resp.json()


def test_create_and_access_investigation(app_client: TestClient, auth_headers: dict):
    case_num = f"CASE-{uuid.uuid4().hex[:6].upper()}"
    create_resp = app_client.post(
        "/api/v1/investigations",
        headers=auth_headers,
        json={
            "title": "Simplification Verification Case",
            "case_number": case_num,
            "description": "Created during Phase S2 verification",
            "status": "OPEN",
        },
    )
    assert create_resp.status_code == 201
    created_case = create_resp.json()
    case_id = created_case["id"]
    assert created_case["case_number"] == case_num

    # Get single investigation details
    detail_resp = app_client.get(f"/api/v1/investigations/{case_id}", headers=auth_headers)
    assert detail_resp.status_code == 200
    assert detail_resp.json()["id"] == case_id
