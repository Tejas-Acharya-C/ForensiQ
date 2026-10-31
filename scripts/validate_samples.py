"""Validate all sample CSVs through the ingestion parser and normalization service."""
import sys, os, uuid
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from pathlib import Path
from app.ingestion.parser import CSVParser
from app.normalization.service import NormalizationService

SAMPLES = [
    ("example_evidence.csv",           "Multi-Stage Compromise (original)"),
    ("sample_normal_workstation.csv",   "Normal Workstation Activity"),
    ("sample_auth_attack.csv",          "Authentication Attack"),
    ("sample_malware_process.csv",      "Malware / Suspicious Process"),
    ("sample_network_c2.csv",           "Network / C2 Activity"),
    ("sample_multistage_compromise.csv","Multi-Stage Compromise (new)"),
]

parser = CSVParser()
svc    = NormalizationService()
ok = True

for fname, label in SAMPLES:
    path = Path("data/examples") / fname
    if not path.exists():
        print(f"[MISSING] {fname}")
        ok = False
        continue

    vr = parser.validate_structure(path)
    if not vr.is_valid:
        print(f"[INVALID] {fname}: {vr.errors}")
        ok = False
        continue

    fake_src = uuid.uuid4()
    fake_inv = uuid.uuid4()
    records  = list(parser.iter_records(path, fake_src))
    good = bad = 0
    for rec in records:
        r = svc.normalize_record(rec, fake_inv)
        if r.is_valid and r.evidence and r.evidence.timestamp:
            good += 1
        else:
            bad += 1

    status = "OK" if bad == 0 else "WARN"
    ml_ok  = "YES" if good >= 10 else "NO (<10)"
    print(f"[{status}] {fname:45} rows={vr.estimated_record_count:3}  norm={good:3}  ml_eligible={ml_ok}")
    if bad > 0:
        print(f"       warning: {bad} records failed normalization")

print()
if ok:
    print("All sample files are structurally valid and parsable.")
    sys.exit(0)
else:
    print("One or more sample files had validation errors.")
    sys.exit(1)
