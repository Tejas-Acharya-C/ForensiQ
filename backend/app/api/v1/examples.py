"""Sample evidence file download endpoints (no authentication required)."""

from pathlib import Path
from typing import List
from pydantic import BaseModel
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

router = APIRouter(tags=["Examples"])

class SampleFileSpec(BaseModel):
    filename: str
    display_name: str

# Catalogue of available sample datasets.
SAMPLE_FILES_LIST = [
    SampleFileSpec(filename="sample_normal_workstation.csv", display_name="Normal Workstation Activity"),
    SampleFileSpec(filename="sample_auth_attack.csv", display_name="Authentication Attack"),
    SampleFileSpec(filename="sample_malware_process.csv", display_name="Suspicious Process / Malware"),
    SampleFileSpec(filename="sample_network_c2.csv", display_name="Network / C2 Activity"),
    SampleFileSpec(filename="sample_multistage_compromise.csv", display_name="Multi-Stage Compromise"),
    SampleFileSpec(filename="example_evidence.csv", display_name="Original Example (Workstation)"),
]

SAMPLE_FILES_DICT = {s.filename: s for s in SAMPLE_FILES_LIST}

def _find_examples_dir() -> Path:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "data" / "examples"
        if candidate.exists():
            return candidate
    return Path("data/examples")

@router.get(
    "/examples",
    response_model=List[SampleFileSpec],
    summary="List available sample evidence files",
)
def list_examples():
    """Return a list of available sample datasets for the frontend to render dynamically."""
    return SAMPLE_FILES_LIST

@router.get(
    "/examples/{filename}",
    summary="Download a specific sample evidence CSV",
    response_class=FileResponse,
)
def download_sample(filename: str):
    if filename not in SAMPLE_FILES_DICT:
        raise HTTPException(status_code=404, detail=f"Sample file '{filename}' not found.")
    
    examples_dir = _find_examples_dir()
    file_path = examples_dir / filename
    
    if not file_path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Sample file '{filename}' is missing from the server. Ensure data/examples/ contains all sample CSVs.",
        )
        
    return FileResponse(
        path=str(file_path),
        filename=filename,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
