"""Pydantic schemas for Phase 1 infrastructure and health endpoints."""

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Health check response schema."""
    status: str = Field(..., description="Overall health status (healthy/degraded/unhealthy)")
    app_name: str = Field(..., description="Application name")
    environment: str = Field(..., description="Active environment mode")
    database_status: str = Field(..., description="Database connectivity status")
    storage_status: str = Field("healthy", description="Evidence storage status (healthy/degraded/unreachable)")
    version: str = Field("0.1.0", description="API version")



class ErrorDetail(BaseModel):
    """Structured error payload."""
    code: str
    message: str
    details: Optional[Dict[str, Any]] = None


class ErrorResponse(BaseModel):
    """Standardized error response schema."""
    success: bool = False
    error: ErrorDetail
