"""Ingestion domain exceptions."""

from typing import Any, Dict, Optional
from fastapi import status
from app.core.errors import ForensiQException


class IngestionError(ForensiQException):
    """Base exception for all ingestion errors."""
    def __init__(
        self,
        message: str,
        error_code: str = "INGESTION_FAILED",
        status_code: int = status.HTTP_400_BAD_REQUEST,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=status_code,
            details=details,
        )


class UnsupportedFileTypeError(IngestionError):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="UNSUPPORTED_FILE_TYPE",
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            details=details,
        )


class InvalidFileError(IngestionError):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="INVALID_FILE",
            status_code=status.HTTP_400_BAD_REQUEST,
            details=details,
        )


class EmptyFileError(IngestionError):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="EMPTY_FILE",
            status_code=status.HTTP_400_BAD_REQUEST,
            details=details,
        )


class FileTooLargeError(IngestionError):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="FILE_TOO_LARGE",
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            details=details,
        )


class DuplicateSourceError(IngestionError):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="DUPLICATE_SOURCE",
            status_code=status.HTTP_409_CONFLICT,
            details=details,
        )
