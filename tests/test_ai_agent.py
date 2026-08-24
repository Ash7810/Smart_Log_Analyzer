import os
import sys
from dotenv import load_dotenv

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Load environment variables
load_dotenv(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".env")))

from backend.ai import generate_explanation_and_root_cause, get_gemini_client

def test_ai_agent():
    print("=" * 70)
    print("TESTING GEMINI AI AGENT EXPLANATION GENERATOR")
    print("=" * 70)

    has_key = bool(os.environ.get("GEMINI_API_KEY"))
    client = get_gemini_client()
    print(f"1. GEMINI_API_KEY present in environment: {has_key}")
    print(f"2. Gemini Client initialized: {client is not None}")

    # Test Sample Anomaly 1: Severity Spike (500 Error)
    print("\n--- Test 1: Severity Spike (Row 225) ---")
    exp1, rc1 = generate_explanation_and_root_cause(
        entry_id=225,
        timestamp="2026-08-20 11:42:00",
        source="10.0.0.55",
        event_type="POST /api/payment",
        severity="error",
        raw_message="POST /api/payment — internal server error",
        detector_rule="severity_spike",
        score_or_reason="isolated 5xx or server error on endpoint (HTTP 500)"
    )
    print("AI Explanation Output:")
    print(exp1)

    # Test Sample Anomaly 2: Off-Hours Access (Row 251)
    print("\n--- Test 2: Off-Hours Sensitive Path Access (Row 251) ---")
    exp2, rc2 = generate_explanation_and_root_cause(
        entry_id=251,
        timestamp="2026-08-20 03:12:00",
        source="203.0.113.7",
        event_type="GET /admin",
        severity="info",
        raw_message="GET /admin — access granted",
        detector_rule="off_hours_access",
        score_or_reason="sensitive path accessed during off-hours (03:12:00)"
    )
    print("AI Explanation Output:")
    print(exp2)

    # Test Sample Anomaly 3: Rare Event Type (Row 254)
    print("\n--- Test 3: Rare Event Type (Row 254) ---")
    exp3, rc3 = generate_explanation_and_root_cause(
        entry_id=254,
        timestamp="2026-08-20 14:03:00",
        source="203.0.113.7",
        event_type="GET /api/export/full-dump",
        severity="info",
        raw_message="GET /api/export/full-dump — status 200",
        detector_rule="rare_event_type",
        score_or_reason="rarely-seen event type 'GET /api/export/full-dump'"
    )
    print("AI Explanation Output:")
    print(exp3)

    print("\n" + "=" * 70)
    print("TEST COMPLETE")
    print("=" * 70)

if __name__ == "__main__":
    test_ai_agent()
