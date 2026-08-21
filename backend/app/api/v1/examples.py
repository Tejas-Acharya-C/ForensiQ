"""Example evidence file download endpoint (no authentication required)."""

from pathlib import Path
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

router = APIRouter(tags=["Examples"])

# Resolve the examples directory relative to the project structure
# Works whether running from backend/ or project root
def _find_examples_dir() -> Path:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "data" / "examples"
        if candidate.exists():
            return candidate
    return Path("data/examples")


@router.get(
    "/examples/example_evidence.csv",
    summary="Download optional example evidence CSV",
    description=(
        "Returns a small example CSV file showing the accepted evidence format. "
        "This file is provided for reference only — it is never automatically imported. "
        "The only required field is 'timestamp'. All other fields are optional."
    ),
    response_class=FileResponse,
    include_in_schema=True,
)
def download_example_evidence():
    """Serve the optional example evidence CSV for user reference."""
    examples_dir = _find_examples_dir()
    file_path = examples_dir / "example_evidence.csv"

    if not file_path.exists():
        raise HTTPException(
            status_code=404,
            detail="Example file not found. The data/examples/example_evidence.csv file may be missing.",
        )

    return FileResponse(
        path=str(file_path),
        filename="example_evidence.csv",
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=example_evidence.csv"},
    )
