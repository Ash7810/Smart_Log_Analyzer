import os
import sys
import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.db import init_db, SessionLocal, LogEntry, FlaggedEntry
from backend.ingestion import validate_and_ingest_csv
from backend.detector import run_anomaly_detection

def detailed_cross_check():
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    logs_path = os.path.join(root_dir, "logs.csv")
    answer_path = os.path.join(root_dir, "answer_key.csv")

    print("=" * 80)
    print("DETAILED CROSS-CHECK AGAINST ANSWER_KEY.CSV")
    print("=" * 80)

    # 1. Initialize DB and Ingest
    init_db()
    db = SessionLocal()
    with open(logs_path, "r", encoding="utf-8") as f:
        csv_text = f.read()

    summary = validate_and_ingest_csv(db, csv_text, filename="logs.csv")
    flagged = run_anomaly_detection(db)

    # 2. Load answer_key.csv
    answer_df = pd.read_csv(answer_path)
    
    # 3. Fetch detected results
    detected_rows = db.query(FlaggedEntry).join(LogEntry).order_by(LogEntry.raw_id.asc()).all()
    detected_map = {f.log_entry.raw_id: f for f in detected_rows}

    # 4. Compare row by row
    matches = 0
    mismatches = []

    print(f"\nTotal Ground Truth Records in answer_key.csv: {len(answer_df)}")
    print(f"Total Detected Anomalies: {len(detected_rows)}\n")
    print(f"{'Row ID':<8} | {'Expected Anomaly Type':<20} | {'Detected Rule':<20} | {'Status':<10}")
    print("-" * 65)

    for _, expected_row in answer_df.iterrows():
        row_id = int(expected_row["row_id"])
        exp_type = expected_row["anomaly_type"]
        exp_reason = expected_row["reason"]

        if row_id in detected_map:
            det = detected_map[row_id]
            det_rule = det.detector_rule
            status = "MATCH"
            matches += 1
        else:
            det_rule = "NOT DETECTED"
            status = "MISSED"
            mismatches.append(row_id)

        print(f"{row_id:<8} | {exp_type:<20} | {det_rule:<20} | {status:<10}")

    # Check for false positives (detected rows not in answer key)
    expected_ids = set(answer_df["row_id"].tolist())
    detected_ids = set(detected_map.keys())
    false_positives = detected_ids - expected_ids

    print("\n" + "=" * 80)
    print("SUMMARY METRICS:")
    print(f"• Expected Anomalies: {len(expected_ids)}")
    print(f"• Detected Anomalies: {len(detected_ids)}")
    print(f"• True Positives (TP): {matches}")
    print(f"• False Positives (FP): {len(false_positives)} {list(false_positives)}")
    print(f"• False Negatives (FN): {len(mismatches)} {mismatches}")
    
    precision = (matches / len(detected_ids)) * 100 if detected_ids else 0
    recall = (matches / len(expected_ids)) * 100 if expected_ids else 0
    
    print(f"• Precision: {precision:.2f}%")
    print(f"• Recall: {recall:.2f}%")
    print("=" * 80)

if __name__ == "__main__":
    detailed_cross_check()
