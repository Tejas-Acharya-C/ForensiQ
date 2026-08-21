"""File format detector for evidence files."""

from pathlib import Path
from typing import Tuple


def detect_file_format(file_path: Path, original_filename: str) -> Tuple[str, str]:
    """Detect evidence file format using content heuristics and fallback extension.

    Returns:
        Tuple of (canonical_format, normalized_extension)
        e.g., ("CSV", ".csv") or ("JSON", ".json") or ("UNSUPPORTED", "")
    """
    if not file_path.exists() or file_path.stat().st_size == 0:
        return "EMPTY", ""

    ext = Path(original_filename).suffix.lower()

    # Read leading bytes for content inspection
    try:
        with open(file_path, "r", encoding="utf-8-sig", errors="replace") as f:
            header_sample = f.read(2048).strip()
    except Exception:
        return "UNSUPPORTED", ext

    if not header_sample:
        return "EMPTY", ext

    # JSON heuristic
    if header_sample.startswith("[") or header_sample.startswith("{"):
        if "\n" in header_sample and header_sample.startswith("{"):
            return "JSONL", ext
        return "JSON", ext

    # Delimited / CSV heuristic (presence of commas, tabs, or common header patterns)
    first_line = header_sample.splitlines()[0]
    if "," in first_line or "\t" in first_line or ext in [".csv", ".tsv", ".log", ".txt"]:
        return "CSV", ext

    return "UNSUPPORTED", ext
