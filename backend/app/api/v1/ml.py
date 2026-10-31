from typing import Optional, Any
import uuid

from fastapi import APIRouter, Depends, BackgroundTasks
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

    service = MLAnomalyService()
    summary: DetectionSummary = service.analyze_source(
        db=db,
        source_id=source_id,
    )

    return {
        "source_id": summary.source_id,
        "status": summary.status,
        "evidence_evaluated": summary.evidence_evaluated,
        "findings_created": summary.findings_created,
        "findings_reused": getattr(summary, "findings_reused", 0)
    }
