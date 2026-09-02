import os
import sys
from app.database.session import SessionLocal
from app.models.investigation import Investigation
from app.report import ReportData, generate_report_pdf

def main():
    db = SessionLocal()
    try:
        inv = db.query(Investigation).first()
        if not inv:
            print("No investigation found to generate a report for.")
            return

        data = ReportData()
        data.investigation = {
            "case_number": inv.case_number,
            "title": inv.title,
            "status": inv.status,
            "created_at": inv.created_at,
        }
        data.summary = {
            "total_sources": 5,
            "total_evidence": 120,
            "total_findings": 15,
            "total_anomalies": 2,
            "total_relationships": 8,
            "total_activities": 4,
            "priority_tier_counts": {
                "CRITICAL": 1,
                "HIGH": 3,
                "MEDIUM": 5,
                "LOW": 6,
            }
        }
        
        # Add some dummy items that test wrapping and tables
        data.findings = [
            {
                "finding_type": "RULE_MATCH",
                "severity": 0.85,
                "rule_id": "SIG_MALWARE_001",
                "mitre_tactic": "Execution",
                "description": "Found a very suspicious executable running from a temporary directory with a long name like C:\\Users\\Administrator\\AppData\\Local\\Temp\\malicious_payload_x86_64_v2.exe",
                "created_at": "2026-08-21T12:00:00Z"
            }
        ] * 15 # Multi-page test
        
        data.activities = [
            {
                "title": "Suspicious Process Execution sequence detected across multiple endpoints",
                "activity_type": "PROCESS_ACTIVITY",
                "status": "NEW",
                "start_time": "2026-08-21T12:00:00Z",
                "evidence_count": 5,
                "finding_count": 2
            }
        ]
        
        data.sources = [
            {
                "filename": "memory_dump_srv01.raw",
                "file_format": "RAW",
                "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "file_size_bytes": 1024*1024*1024*4,
                "ingestion_status": "COMPLETED",
                "ingested_at": "2026-08-21T11:00:00Z"
            }
        ]

        pdf_bytes = generate_report_pdf(data)
        
        output_path = f"ForensiQ_Test_{inv.case_number}.pdf"
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)
            
        print(f"Generated test report successfully: {output_path}")

    finally:
        db.close()

if __name__ == "__main__":
    main()
