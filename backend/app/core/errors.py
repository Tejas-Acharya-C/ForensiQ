"""Standardized application error definitions and exception handlers."""

from typing import Any, Dict, Optional
from fastapi import Request, status
from fastapi.responses import JSONResponse


class ForensiQException(Exception):
    """Base exception for all ForensiQ domain and application errors."""

    def __init__(
        self,
        message: str,
        error_code: str = "INTERNAL_ERROR",
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        self.details = details or {}


class BadRequestError(ForensiQException):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="BAD_REQUEST",
            status_code=status.HTTP_400_BAD_REQUEST,
            details=details,
        )


class NotFoundError(ForensiQException):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND,
            details=details,
        )


class ConflictError(ForensiQException):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="CONFLICT",
            status_code=status.HTTP_409_CONFLICT,
            details=details,
        )


class ProcessingError(ForensiQException):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="PROCESSING_ERROR",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            details=details,
        )


class RateLimitError(ForensiQException):
    def __init__(self, message: str = "Rate limit exceeded. Please retry after cooldown period.", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="RATE_LIMIT_EXCEEDED",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            details=details,
        )


async def forensiq_exception_handler(request: Request, exc: ForensiQException) -> JSONResponse:
    """Sanitized global exception handler for domain exceptions."""
    payload = {
        "success": False,
        "error": {
            "code": exc.error_code,
            "message": exc.message,
            "details": exc.details,
        },
    }
    return JSONResponse(status_code=exc.status_code, content=payload)


async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Fallback handler to prevent internal tracebacks or secrets leaking to clients."""
    payload = {
        "success": False,
        "error": {
            "code": "INTERNAL_ERROR",
            "message": "An unexpected internal server error occurred.",
            "details": {},
        },
    }
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=payload,
    )
