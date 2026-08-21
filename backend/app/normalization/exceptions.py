"""Normalization exceptions."""

from typing import Any, Dict, Optional
from fastapi import status
from app.core.errors import ForensiQException


class NormalizationError(ForensiQException):
    """Base exception for normalization failures."""
    def __init__(
        self,
        message: str,
        error_code: str = "NORMALIZATION_FAILED",
        status_code: int = status.HTTP_400_BAD_REQUEST,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=status_code,
            details=details,
        )


class TimestampNormalizationError(NormalizationError):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="INVALID_TIMESTAMP",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            details=details,
        )


class MappingError(NormalizationError):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="MAPPING_ERROR",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            details=details,
        )
