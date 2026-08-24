"""
Test script verifying ingestion validation and rule-based anomaly detector
against logs.csv and answer_key.csv
"""
import os
import sys
import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.db import init_db, SessionLocal, LogEntry, FlaggedEntry, IngestionSummary
from backend.ingestion import validate_and_ingest_csv
from backend.detector import run_anomaly_detection

def run_test():
    print("=== 1. Initializing DB ===")
    init_db()
    db = SessionLocal()

    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    logs_path = os.path.join(root_dir, "logs.csv")
    answer_path = os.path.join(root_dir, "answer_key.csv")

    with open(logs_path, "r", encoding="utf-8") as f:
        csv_text = f.read()

    print("=== 2. Running Ingestion & Validation ===")
    summary = validate_and_ingest_csv(db, csv_text, filename="logs.csv")
    print(f"Total Rows: {summary.total_rows}")
    print(f"Valid Rows: {summary.valid_rows}")
    print(f"Rejected Rows: {summary.rejected_rows}")
    print(f"Rejections: {summary.rejection_details}")

    assert summary.rejected_rows == 2, f"Expected 2 rejections, got {summary.rejected_rows}"
    assert summary.valid_rows == 255, f"Expected 255 valid rows, got {summary.valid_rows}"

    print("=== 3. Running Deterministic Anomaly Detector ===")
    flagged = run_anomaly_detection(db)
    print(f"Total Flagged Anomalies: {len(flagged)}")

    # Compare with answer_key.csv
    answer_df = pd.read_csv("answer_key.csv")
    expected_ids = set(answer_df["row_id"].tolist())
    
    flagged_entries = db.query(FlaggedEntry).join(LogEntry).all()
    detected_raw_ids = {f.log_entry.raw_id for f in flagged_entries}

    print(f"Expected Flagged IDs ({len(expected_ids)}): {sorted(list(expected_ids))}")
    print(f"Detected Flagged IDs ({len(detected_raw_ids)}): {sorted(list(detected_raw_ids))}")

    missing = expected_ids - detected_raw_ids
    extra = detected_raw_ids - expected_ids

    print(f"Missing detections: {missing}")
    print(f"Extra detections: {extra}")

    assert missing == set(), f"Missed anomalies: {missing}"
    print("\n>>> ALL TEST ASSERTIONS PASSED! Detector matched 100% of answer_key.csv <<<")

if __name__ == "__main__":
    run_test()
