"""Centralized structured logging configuration for ForensiQ."""

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Dict


class JSONFormatter(logging.Formatter):
    """Custom JSON log formatter for structured output."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "module": record.module,
            "name": record.name,
            "message": record.getMessage(),
        }

        # Include request/correlation ID if present
        if hasattr(record, "request_id"):
            log_entry["request_id"] = record.request_id

        # Include exception info if available
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry)


def setup_logging(log_level: str = "INFO", json_format: bool = False) -> None:
    """Configure root and application loggers."""
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(numeric_level)

    if json_format:
        handler.setFormatter(JSONFormatter())
    else:
        standard_format = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
        handler.setFormatter(standard_format)

    root_logger.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Obtain a named logger instance."""
    return logging.getLogger(f"forensiq.{name}")
