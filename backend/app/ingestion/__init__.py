"""Ingestion package export registry."""

from app.ingestion.contracts import RawEvidenceRecord, ValidationResult, IngestionResult
from app.ingestion.service import IngestionService
from app.ingestion.detector import detect_file_format
from app.ingestion.exceptions import (
    IngestionError,
    UnsupportedFileTypeError,
    InvalidFileError,
    EmptyFileError,
    FileTooLargeError,
    DuplicateSourceError,
)

__all__ = [
    "RawEvidenceRecord",
    "ValidationResult",
    "IngestionResult",
    "IngestionService",
    "detect_file_format",
    "IngestionError",
    "UnsupportedFileTypeError",
    "InvalidFileError",
    "EmptyFileError",
    "FileTooLargeError",
    "DuplicateSourceError",
]
