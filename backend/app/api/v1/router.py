"""API v1 root router aggregation."""

from fastapi import APIRouter
from app.api.v1.auth import router as auth_router
from app.api.v1.health import router as health_router
from app.api.v1.evidence import router as evidence_router
from app.api.v1.detection import router as detection_router
from app.api.v1.ml import router as ml_router
from app.api.v1.correlation import router as correlation_router
from app.api.v1.activities import router as activities_router
from app.api.v1.prioritization import router as prioritization_router
from app.api.v1.investigations import router as investigations_router
from app.api.v1.examples import router as examples_router
from app.api.v1.report import router as report_router

api_v1_router = APIRouter()

# Register routes
api_v1_router.include_router(auth_router)
api_v1_router.include_router(health_router)
api_v1_router.include_router(investigations_router)
api_v1_router.include_router(evidence_router)
api_v1_router.include_router(detection_router)
api_v1_router.include_router(ml_router)
api_v1_router.include_router(correlation_router)
api_v1_router.include_router(activities_router)
api_v1_router.include_router(prioritization_router)
api_v1_router.include_router(examples_router)
api_v1_router.include_router(report_router)

