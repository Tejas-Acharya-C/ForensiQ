"""File-system security utilities for ForensiQ.

Retained after authentication removal:
  sanitize_filename  — used by ingestion/service.py to sanitize uploaded filenames.
  validate_file_path — used by core/storage.py to prevent path traversal.

Removed (authentication-only):
  hash_password, verify_password, create_access_token, decode_access_token.
"""

import os
import posixpath
import re
from pathlib import Path


def sanitize_filename(filename: str) -> str:
    """Sanitize uploaded filenames across all OS platforms to prevent directory traversal and injection attacks."""
    if not filename or not isinstance(filename, str):
        return "unnamed_evidence"

    # Neutralize null bytes and whitespace
    cleaned = filename.replace("\x00", "").strip()
    if not cleaned:
        return "unnamed_evidence"

    # Normalize Windows drive letter if present (e.g., C:\...)
    cleaned = re.sub(r"^[a-zA-Z]:", "", cleaned)

    # Normalize both Windows and POSIX path separators to forward slash
    normalized = cleaned.replace("\\", "/")

    # Extract basename deterministically using POSIX path semantics
    base_name = posixpath.basename(normalized.rstrip("/"))

    # Strip any characters that are not alphanumeric, dots, underscores, or hyphens
    sanitized = re.sub(r"[^a-zA-Z0-9._-]", "_", base_name)

    # Strip leading dots to neutralize hidden files and directory traversal remnants
    sanitized = sanitized.lstrip(".")

    return sanitized or "unnamed_evidence"


def validate_file_path(base_dir: Path, target_path: Path) -> bool:
    """Verify that a target file path remains safely within the designated base directory."""
    try:
        resolved_base = base_dir.resolve()
        resolved_target = target_path.resolve()
        return resolved_target.is_relative_to(resolved_base)
    except (ValueError, RuntimeError):
        return False
