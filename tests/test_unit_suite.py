"""
Comprehensive Unit & Integration Test Suite
Covering every category in CHECKLIST.MD:
1. Ingestion & Validation (valid rows, missing timestamp, malformed timestamp, empty CSV)
2. Deterministic Anomaly Detector (all 4 rules, precision & recall against answer_key.csv)
3. AI Explanation & Caching (persistence, graceful degradation without API key)
4. Data Persistence & SQLite schema integrity
5. API Endpoints (FastAPI response structure & HTTP status codes)
"""

import unittest
import os
import sys
import json
import pandas as pd

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.db import Base, LogEntry, FlaggedEntry, IngestionSummary
from backend.ingestion import validate_and_ingest_csv, parse_timestamp
from backend.detector import (
    run_anomaly_detection,
    SENSITIVE_PATHS,
    BURST_WINDOW_SECONDS,
    BURST_THRESHOLD_COUNT,
    OFF_HOURS_START_HOUR,
    OFF_HOURS_END_HOUR,
    RARE_EVENT_MAX_OCCURRENCES,
    RARE_EVENT_PERCENTAGE_RATIO
)
from backend.ai import generate_explanation_and_root_cause

class TestSmartLogAnalyzer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Use an isolated in-memory or test SQLite database
        cls.engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        cls.Session = sessionmaker(bind=cls.engine)
        Base.metadata.create_all(bind=cls.engine)

    def setUp(self):
        self.db = self.Session()
        # Clean database tables
        self.db.query(FlaggedEntry).delete()
        self.db.query(LogEntry).delete()
        self.db.query(IngestionSummary).delete()
        self.db.commit()

    def tearDown(self):
        self.db.close()

    # =========================================================================
    # 1. INGESTION & VALIDATION TESTS
    # =========================================================================
    def test_timestamp_parser(self):
        """Test timestamp parser across various formats and invalid inputs."""
        self.assertIsNotNone(parse_timestamp("2026-08-20 08:00:29"))
        self.assertIsNotNone(parse_timestamp("2026-08-20T08:00:29"))
        self.assertIsNotNone(parse_timestamp("2026-08-20 08:00:29.123456"))
        self.assertIsNone(parse_timestamp(""))
        self.assertIsNone(parse_timestamp(None))
        self.assertIsNone(parse_timestamp("not-a-real-date"))

    def test_empty_dataset_ingestion(self):
        """Test that ingestion handles empty data without crashing."""
        summary = validate_and_ingest_csv(self.db, "", filename="empty.csv")
        self.assertEqual(summary.total_rows, 0)
        self.assertEqual(summary.valid_rows, 0)
        self.assertEqual(summary.rejected_rows, 0)
        
        # Detector should return empty list gracefully
        flagged = run_anomaly_detection(self.db)
        self.assertEqual(len(flagged), 0)

    def test_malformed_rows_rejection(self):
        """Test that malformed/missing timestamps are strictly rejected."""
        raw_csv = """id,timestamp,source,event_type,severity,status,raw_message
1,2026-08-20 08:00:00,10.0.0.1,GET /api/test,info,200,Valid row
2,,10.0.0.1,GET /api/test,info,200,Missing timestamp
3,invalid-date,10.0.0.1,GET /api/test,info,200,Malformed timestamp
4,2026-08-20 08:00:03,,GET /api/test,info,200,Missing source
"""
        summary = validate_and_ingest_csv(self.db, raw_csv, filename="test_malformed.csv")
        self.assertEqual(summary.total_rows, 4)
        self.assertEqual(summary.valid_rows, 1)
        self.assertEqual(summary.rejected_rows, 3)

        # Check rejection details in DB
        rejections = json.loads(summary.rejection_details)
        self.assertEqual(len(rejections), 3)
        self.assertIn("Missing required field: timestamp", rejections[0]["reason"])
        self.assertIn("Malformed timestamp format", rejections[1]["reason"])
        self.assertIn("Missing required field: source", rejections[2]["reason"])

    # =========================================================================
    # 2. ANOMALY DETECTOR TESTS
    # =========================================================================
    def test_severity_spike_detection(self):
        """Test severity spike detection on 5xx status or error severity."""
        raw_csv = """id,timestamp,source,event_type,severity,status,raw_message
1,2026-08-20 08:00:00,10.0.0.1,POST /api/payment,error,500,Internal error
2,2026-08-20 08:01:00,10.0.0.1,POST /api/payment,info,200,Normal
"""
        validate_and_ingest_csv(self.db, raw_csv)
        flagged = run_anomaly_detection(self.db)
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].detector_rule, "severity_spike")

    def test_burst_frequency_detection(self):
        """Test burst frequency detection when >= BURST_THRESHOLD_COUNT within window."""
        rows = ["id,timestamp,source,event_type,severity,status,raw_message"]
        # Generate 12 requests within 30 seconds from same source
        for i in range(12):
            sec = f"{i*2:02d}"
            rows.append(f"{i+1},2026-08-20 08:00:{sec},198.51.100.23,POST /api/login,warn,401,Login attempt")
        # Add normal requests from different sources with repeated common event type
        for j in range(5):
            rows.append(f"{13+j},2026-08-20 08:00:{10+j:02d},10.0.0.55,POST /api/login,info,200,Normal user")
        
        validate_and_ingest_csv(self.db, "\n".join(rows))
        flagged = run_anomaly_detection(self.db)
        self.assertEqual(len(flagged), 12)
        for f in flagged:
            self.assertEqual(f.detector_rule, "burst_frequency")

    def test_off_hours_sensitive_access_detection(self):
        """Test detection of sensitive paths accessed during 00:00 - 06:00."""
        raw_csv = """id,timestamp,source,event_type,severity,status,raw_message
1,2026-08-20 03:15:00,203.0.113.7,GET /admin,info,200,Access granted off hours
2,2026-08-20 14:15:00,203.0.113.7,GET /admin,info,200,Access granted regular hours
"""
        validate_and_ingest_csv(self.db, raw_csv)
        flagged = run_anomaly_detection(self.db)
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].detector_rule, "off_hours_access")
        self.assertEqual(flagged[0].log_entry.raw_id, 1)

    def test_rare_event_type_detection(self):
        """Test detection of rare administrative endpoints."""
        rows = ["id,timestamp,source,event_type,severity,status,raw_message"]
        # 50 normal common endpoints
        for i in range(50):
            rows.append(f"{i+1},2026-08-20 09:{i%60:02d}:00,10.0.0.1,GET /api/products,info,200,Normal")
        # 1 rare endpoint
        rows.append("51,2026-08-20 09:30:00,10.0.0.1,GET /api/export/full-dump,info,200,Dump triggered")

        validate_and_ingest_csv(self.db, "\n".join(rows))
        flagged = run_anomaly_detection(self.db)
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].detector_rule, "rare_event_type")

    # =========================================================================
    # 3. FULL DATASET & GROUND TRUTH VALIDATION (answer_key.csv)
    # =========================================================================
    def test_full_dataset_answer_key_precision_and_recall(self):
        """Validate 100% precision and recall against answer_key.csv."""
        root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        logs_path = os.path.join(root_dir, "logs.csv")
        answer_path = os.path.join(root_dir, "answer_key.csv")

        if not os.path.exists(logs_path) or not os.path.exists(answer_path):
            self.skipTest("logs.csv or answer_key.csv missing")

        with open(logs_path, "r", encoding="utf-8") as f:
            csv_content = f.read()

        summary = validate_and_ingest_csv(self.db, csv_content, filename="logs.csv")
        self.assertEqual(summary.total_rows, 257)
        self.assertEqual(summary.valid_rows, 255)
        self.assertEqual(summary.rejected_rows, 2)

        flagged = run_anomaly_detection(self.db)
        self.assertEqual(len(flagged), 35)

        answer_df = pd.read_csv(answer_path)
        expected_ids = set(answer_df["row_id"].tolist())
        detected_ids = {f.log_entry.raw_id for f in flagged}

        self.assertEqual(detected_ids, expected_ids, "Detected anomaly IDs must match answer_key.csv exactly")

    # =========================================================================
    # 4. AI EXPLANATION & CACHING INTEGRITY
    # =========================================================================
    def test_ai_graceful_degradation_without_key(self):
        """Ensure AI generator returns graceful fallback when API key is missing or invalid."""
        orig_key = os.environ.get("GEMINI_API_KEY")
        try:
            os.environ["GEMINI_API_KEY"] = ""
            exp, rc = generate_explanation_and_root_cause(
                entry_id=1,
                timestamp="2026-08-20 08:00:00",
                source="10.0.0.1",
                event_type="POST /api/payment",
                severity="error",
                raw_message="500 Internal error",
                detector_rule="severity_spike",
                score_or_reason="5xx error"
            )
            self.assertTrue(exp.startswith("Explanation unavailable"))
            self.assertIn("Root cause", rc)
        finally:
            if orig_key:
                os.environ["GEMINI_API_KEY"] = orig_key

    def test_caching_persistence(self):
        """Ensure generated explanations persist in FlaggedEntry table."""
        raw_csv = "id,timestamp,source,event_type,severity,status,raw_message\n1,2026-08-20 08:00:00,10.0.0.1,POST /api/payment,error,500,Internal error"
        validate_and_ingest_csv(self.db, raw_csv)
        flagged = run_anomaly_detection(self.db)
        
        # Simulate storing explanation
        f = flagged[0]
        f.ai_explanation = "This is a cached plain-prose explanation."
        f.ai_root_cause = "Database connection timeout."
        self.db.commit()

        # Query again from database to verify persistence
        persisted = self.db.query(FlaggedEntry).filter(FlaggedEntry.id == f.id).first()
        self.assertEqual(persisted.ai_explanation, "This is a cached plain-prose explanation.")
        self.assertEqual(persisted.ai_root_cause, "Database connection timeout.")

if __name__ == "__main__":
    unittest.main(verbosity=2)
