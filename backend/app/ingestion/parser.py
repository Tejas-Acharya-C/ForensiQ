"""Robust parsers for evidence file formats."""

import csv
import json
import uuid
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator, List, Dict, Any

from app.ingestion.contracts import ValidationResult, RawEvidenceRecord


class BaseEvidenceParser(ABC):
    """Abstract interface defining structural validation and chunked record iteration."""

    @abstractmethod
    def validate_structure(self, file_path: Path) -> ValidationResult:
        """Inspect file structure, headers, syntax, and estimate record counts."""
        pass

    @abstractmethod
    def iter_records(
        self,
        file_path: Path,
        source_id: uuid.UUID,
        chunk_size: int = 10000,
    ) -> Iterator[RawEvidenceRecord]:
        """Stream raw records with deterministic source offset references."""
        pass


def detect_file_encoding(file_path: Path) -> str:
    """Inspect byte markers (BOM) deterministically to detect UTF-16, UTF-8-SIG, or default UTF-8."""
    with open(file_path, "rb") as f:
        header = f.read(4)

    if header.startswith(b"\xff\xfe") or header.startswith(b"\xfe\xff"):
        return "utf-16"
    if header.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    return "utf-8"


class CSVParser(BaseEvidenceParser):
    """Parser for structured CSV and delimited tabular evidence files."""

    def validate_structure(self, file_path: Path) -> ValidationResult:
        errors: List[str] = []
        warnings: List[str] = []
        preview_records: List[Dict[str, Any]] = []
        row_count = 0

        try:
            if not file_path.exists() or file_path.stat().st_size == 0:
                return ValidationResult(is_valid=False, detected_format="CSV", errors=["File is empty or does not exist."])

            encoding = detect_file_encoding(file_path)

            with open(file_path, "r", encoding=encoding, errors="strict") as f:
                reader = csv.DictReader(f)
                if not reader.fieldnames:
                    return ValidationResult(is_valid=False, detected_format="CSV", errors=["CSV file lacks a valid header row."])

                if any(col is None or col.strip() == "" for col in reader.fieldnames):
                    warnings.append("CSV contains one or more empty header column names.")

                for idx, row in enumerate(reader):
                    row_count += 1
                    if idx < 10:
                        cleaned_row = {k: v for k, v in row.items() if k is not None}
                        preview_records.append(cleaned_row)

            if row_count == 0:
                return ValidationResult(is_valid=False, detected_format="CSV", errors=["CSV file contains a header but zero data records."])

            return ValidationResult(
                is_valid=True,
                detected_format="CSV",
                estimated_record_count=row_count,
                errors=errors,
                warnings=warnings,
                preview_records=preview_records,
            )

        except UnicodeDecodeError:
            return ValidationResult(is_valid=False, detected_format="CSV", errors=[f"Forensic decoding failed."])
        except Exception as exc:
            return ValidationResult(is_valid=False, detected_format="CSV", errors=[f"CSV structural parsing failed: {str(exc)}"])

    def iter_records(self, file_path: Path, source_id: uuid.UUID, chunk_size: int = 10000) -> Iterator[RawEvidenceRecord]:
        encoding = detect_file_encoding(file_path)
        with open(file_path, "r", encoding=encoding, errors="strict") as f:
            reader = csv.DictReader(f)
            for offset, row in enumerate(reader):
                cleaned_row = {k: (v if v is not None else "") for k, v in row.items() if k is not None}
                yield RawEvidenceRecord(
                    source_id=source_id,
                    record_offset=offset,
                    raw_data=cleaned_row,
                    source_format="CSV",
                )


class JSONParser(BaseEvidenceParser):
    """Parser for standard JSON array and JSON Lines (NDJSON) evidence files."""

    def _is_json_lines(self, file_path: Path) -> bool:
        encoding = detect_file_encoding(file_path)
        with open(file_path, "r", encoding=encoding, errors="strict") as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    return stripped.startswith("{")
        return False

    def validate_structure(self, file_path: Path) -> ValidationResult:
        errors: List[str] = []
        warnings: List[str] = []
        preview_records: List[Dict[str, Any]] = []
        record_count = 0

        try:
            if not file_path.exists() or file_path.stat().st_size == 0:
                return ValidationResult(is_valid=False, detected_format="JSON", errors=["File is empty or does not exist."])

            encoding = detect_file_encoding(file_path)
            is_jsonl = self._is_json_lines(file_path)

            if is_jsonl:
                with open(file_path, "r", encoding=encoding, errors="strict") as f:
                    for line_idx, line in enumerate(f):
                        line_str = line.strip()
                        if not line_str: continue
                        try:
                            item = json.loads(line_str)
                            if not isinstance(item, dict):
                                errors.append(f"Line {line_idx} contains a non-object JSON value.")
                                break
                            record_count += 1
                            if line_idx < 10: preview_records.append(item)
                        except json.JSONDecodeError as jde:
                            errors.append(f"Line {line_idx} is malformed JSON: {str(jde)}")
                            break
                format_name = "JSONL"
            else:
                with open(file_path, "r", encoding=encoding, errors="strict") as f:
                    data = json.load(f)
                    if not isinstance(data, list):
                        return ValidationResult(is_valid=False, detected_format="JSON", errors=["Standard JSON file must contain a top-level array of objects."])
                    record_count = len(data)
                    for idx, item in enumerate(data):
                        if not isinstance(item, dict):
                            errors.append(f"Item at index {idx} is not a valid JSON object.")
                            break
                        if idx < 10: preview_records.append(item)
                format_name = "JSON"

            if errors:
                return ValidationResult(is_valid=False, detected_format=format_name, errors=errors, warnings=warnings)

            if record_count == 0:
                return ValidationResult(is_valid=False, detected_format=format_name, errors=["JSON evidence source contains 0 records."])

            return ValidationResult(
                is_valid=True,
                detected_format=format_name,
                estimated_record_count=record_count,
                preview_records=preview_records,
                warnings=warnings,
            )

        except UnicodeDecodeError:
            return ValidationResult(is_valid=False, detected_format="JSON", errors=[f"Forensic decoding failed."])
        except Exception as exc:
            return ValidationResult(is_valid=False, detected_format="JSON", errors=[f"JSON syntax validation failed: {str(exc)}"])

    def iter_records(self, file_path: Path, source_id: uuid.UUID, chunk_size: int = 10000) -> Iterator[RawEvidenceRecord]:
        encoding = detect_file_encoding(file_path)
        is_jsonl = self._is_json_lines(file_path)

        if is_jsonl:
            with open(file_path, "r", encoding=encoding, errors="strict") as f:
                offset = 0
                for line in f:
                    stripped = line.strip()
                    if not stripped: continue
                    item = json.loads(stripped)
                    if isinstance(item, dict):
                        yield RawEvidenceRecord(source_id=source_id, record_offset=offset, raw_data=item, source_format="JSONL")
                        offset += 1
        else:
            with open(file_path, "r", encoding=encoding, errors="strict") as f:
                data = json.load(f)
                for offset, item in enumerate(data):
                    if isinstance(item, dict):
                        yield RawEvidenceRecord(source_id=source_id, record_offset=offset, raw_data=item, source_format="JSON")
