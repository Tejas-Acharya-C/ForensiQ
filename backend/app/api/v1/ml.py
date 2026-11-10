from typing import Optional, Any
import uuid

from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import (
    check_source_access,
    rate_limit_analysis,
)
from app.database.session import get_db
from app.detection import MLAnomalyService, DetectionSummary

router = APIRouter(prefix="/ml", tags=["ML Anomaly Detection"])


class MLAnalysisRequest(BaseModel):
    contamination: Optional[float] = 0.05
    random_seed: Optional[int] = 42
    model_override: Optional[str] = None
    threshold: Optional[float] = None


@router.post("/sources/{source_id}/analyze")
def analyze_source_ml(
    source_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    payload: Optional[MLAnalysisRequest] = None,
    db: Session = Depends(get_db),
    _rate_limit: None = Depends(rate_limit_analysis),
) -> Any:
    """Run ML anomaly detection over all normalized evidence records with rate limiting."""
    check_source_access(source_id, db)

    if payload and payload.model_override:
        clean_model = payload.model_override.strip().lower()
        if clean_model not in ("isolation_forest", "isolationforest"):
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported model override '{payload.model_override}'. Only 'isolation_forest' is supported.",
            )

    service = MLAnomalyService()
    contamination = payload.contamination if payload else None
    random_seed = payload.random_seed if payload else None
    threshold = payload.threshold if payload else None
    summary: DetectionSummary = service.analyze_source(
        db=db,
        source_id=source_id,
        contamination=contamination,
        random_seed=random_seed,
        threshold_override=threshold,
    )

    return {
        "source_id": summary.source_id,
        "status": summary.status,
        "evidence_evaluated": summary.evidence_evaluated,
        "findings_created": summary.findings_created,
        "findings_reused": getattr(summary, "findings_reused", 0)
    }
