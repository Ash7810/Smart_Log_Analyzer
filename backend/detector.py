from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from backend.db import LogEntry, FlaggedEntry, IngestionSummary

# Detection Rule Configurable Thresholds
SENSITIVE_PATHS = ["/admin", "/api/internal", "/api/export", "/debug", "/root", "/api/config"]
OFF_HOURS_START_HOUR = 0   # 00:00 (12 AM)
OFF_HOURS_END_HOUR = 6     # 06:00 (6 AM)
BURST_WINDOW_SECONDS = 60  # Sliding time window in seconds
BURST_THRESHOLD_COUNT = 10 # Minimum requests in window to trigger burst flag
RARE_EVENT_MAX_OCCURRENCES = 2
RARE_EVENT_PERCENTAGE_RATIO = 0.015  # <1.5% frequency

def run_anomaly_detection(db: Session) -> List[FlaggedEntry]:
    """
    Pure deterministic rule-based anomaly detector.
    Does NOT use AI or ML model.
    Implements:
    1. Severity Spike (5xx error code or severity in 'error'/'critical')
    2. Burst Frequency (Excessive requests from same source within rolling time window)
    3. Off-Hours Access (Sensitive/admin path requests during off-hours 00:00-06:00)
    4. Rare Event Type (Rare/unusual endpoint operations)
    """
    # Clear existing flagged entries
    db.query(FlaggedEntry).delete()
    db.commit()

    valid_entries = db.query(LogEntry).filter(LogEntry.is_valid == True).order_by(LogEntry.timestamp.asc()).all()
    if not valid_entries:
        return []

    # Pre-calculate frequency distributions for rare event detection
    total_valid = len(valid_entries)
    event_type_counts: Dict[str, int] = {}
    for entry in valid_entries:
        et = (entry.event_type or "").strip()
        event_type_counts[et] = event_type_counts.get(et, 0) + 1

    # Frequency threshold: event types that appear <= RARE_EVENT_MAX_OCCURRENCES or < RARE_EVENT_PERCENTAGE_RATIO of total dataset
    rare_threshold = max(RARE_EVENT_MAX_OCCURRENCES, int(total_valid * RARE_EVENT_PERCENTAGE_RATIO))

    # Helper tracking for burst detection: window per source
    source_timestamps: Dict[str, List[Tuple[datetime, int]]] = {}  # source -> list of (timestamp, entry_id)
    burst_flagged_ids = set()

    for entry in valid_entries:
        src = entry.source
        ts = entry.timestamp
        if not src or not ts:
            continue
        if src not in source_timestamps:
            source_timestamps[src] = []
        source_timestamps[src].append((ts, entry.id))

    # Identify bursts in O(N) linear time using a two-pointer sliding window queue per source
    for src, ts_list in source_timestamps.items():
        n = len(ts_list)
        left = 0
        for right in range(n):
            # Advance left pointer until window is within BURST_WINDOW_SECONDS
            while (ts_list[right][0] - ts_list[left][0]).total_seconds() > BURST_WINDOW_SECONDS:
                left += 1
            # If current window has >= BURST_THRESHOLD_COUNT events, flag all events in window
            if (right - left + 1) >= BURST_THRESHOLD_COUNT:
                for k in range(left, right + 1):
                    burst_flagged_ids.add(ts_list[k][1])

    flagged_objects = []

    for entry in valid_entries:
        reasons = []
        rules = []
        scores = []

        # Rule 1: Severity Spike (5xx error code or severity error/critical)
        is_5xx = entry.status is not None and 500 <= entry.status <= 599
        is_sev_err = entry.severity in ["error", "critical"]
        if is_5xx or is_sev_err:
            rules.append("severity_spike")
            status_desc = f"HTTP {entry.status}" if entry.status else f"severity '{entry.severity}'"
            scores.append("High (0.95)")
            reasons.append(f"isolated 5xx or server error on endpoint ({status_desc})")

        # Rule 2: Burst Frequency (high-speed request spam from single source)
        if entry.id in burst_flagged_ids:
            rules.append("burst_frequency")
            scores.append("High (0.90)")
            reasons.append(f"high frequency request burst from source {entry.source} (>=10 reqs/min)")

        # Rule 3: Off-Hours Access to Sensitive Paths
        if entry.timestamp:
            hour = entry.timestamp.hour
            is_off_hours = OFF_HOURS_START_HOUR <= hour < OFF_HOURS_END_HOUR
            is_sensitive = any(path in (entry.event_type or "") or path in (entry.raw_message or "") for path in SENSITIVE_PATHS)
            if is_off_hours and is_sensitive:
                rules.append("off_hours_access")
                scores.append("Critical (0.98)")
                reasons.append(f"sensitive path accessed during off-hours ({entry.timestamp.strftime('%H:%M:%S')})")

        # Rule 4: Rare Event Type (only evaluated when total dataset size >= 10 and event is genuinely infrequent)
        et = (entry.event_type or "").strip()
        if total_valid >= 10 and et and event_type_counts.get(et, 0) <= rare_threshold and event_type_counts[et] < total_valid * 0.1 and not any(r in rules for r in ["off_hours_access", "severity_spike"]):
            rules.append("rare_event_type")
            scores.append("Medium (0.75)")
            reasons.append(f"rarely-seen event type '{et}' (occurred only {event_type_counts[et]} time(s))")

        if rules:
            primary_rule = rules[0]
            primary_score = scores[0]
            primary_reason = "; ".join(reasons)

            flagged = FlaggedEntry(
                log_entry_id=entry.id,
                detector_rule=primary_rule,
                score=primary_score,
                reason=primary_reason,
                ai_explanation=None,
                ai_root_cause=None
            )
            flagged_objects.append(flagged)

    if flagged_objects:
        db.bulk_save_objects(flagged_objects)
        db.commit()

    # Update summary with count
    latest_summary = db.query(IngestionSummary).order_by(IngestionSummary.id.desc()).first()
    if latest_summary:
        latest_summary.flagged_rows = len(flagged_objects)
        db.commit()

    return db.query(FlaggedEntry).all()
