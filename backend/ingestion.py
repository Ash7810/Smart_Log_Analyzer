import io
import csv
import json
from datetime import datetime
from typing import List, Dict, Tuple, Any
from sqlalchemy.orm import Session
from backend.db import LogEntry, IngestionSummary

DATE_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%d",
]

def parse_timestamp(ts_str: str):
    if not ts_str or not isinstance(ts_str, str):
        return None
    ts_str = ts_str.strip()
    if not ts_str:
        return None
    # Fast path for standard ISO / SQLite format
    if len(ts_str) >= 19 and ts_str[4] == '-' and ts_str[7] == '-':
        try:
            # Replaces T with space and strips fractional seconds for fast parsing
            clean_ts = ts_str.replace("T", " ")
            if "." in clean_ts:
                return datetime.strptime(clean_ts, "%Y-%m-%d %H:%M:%S.%f")
            return datetime.strptime(clean_ts, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
    for fmt in DATE_FORMATS:
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return None

def validate_and_ingest_csv(db: Session, csv_content: str, filename: str = "logs.csv") -> IngestionSummary:
    """
    High-performance CSV ingestion and schema validation supporting 100,000+ rows.
    """
    # Clean old records if doing a full re-ingestion
    db.query(LogEntry).delete()
    db.commit()

    reader = csv.DictReader(io.StringIO(csv_content.strip()))
    if not reader.fieldnames:
        summary = IngestionSummary(
            filename=filename,
            total_rows=0,
            valid_rows=0,
            rejected_rows=0,
            flagged_rows=0,
            rejection_details=json.dumps([])
        )
        db.add(summary)
        db.commit()
        return summary

    total = 0
    valid_count = 0
    rejected_count = 0
    rejection_details = []

    entries_to_add = []

    # Flexible column mapping dictionary
    def get_field_val(row_dict: dict, candidates: list) -> str:
        for c in candidates:
            if c in row_dict and row_dict[c] is not None:
                val = str(row_dict[c]).strip()
                if val:
                    return val
        return ""

    for idx, row in enumerate(reader, start=1):
        total += 1
        # Normalize keys to lowercase for flexible matching
        norm_row = {k.strip().lower().replace(" ", "_"): v for k, v in row.items() if k}

        # ID mapping
        raw_id_str = get_field_val(norm_row, ["id", "row_id", "session_id", "index"]) or str(idx)
        try:
            raw_id = int(raw_id_str)
        except ValueError:
            raw_id = idx

        # Timestamp mapping
        raw_ts = get_field_val(norm_row, ["timestamp", "time", "datetime", "date", "@timestamp", "ts"])

        # Source / IP mapping
        source = get_field_val(norm_row, ["source", "ip_address", "ip", "client_ip", "src_ip", "host", "user", "location"])

        # Event Type / Request Type / Path mapping
        event_type = get_field_val(norm_row, ["event_type", "request_type", "method", "action", "endpoint", "path", "uri", "event", "user_agent"])

        # Status / HTTP code mapping
        status_str = get_field_val(norm_row, ["status", "status_code", "http_status", "code", "response_code"])
        status_val = None
        if status_str:
            try:
                status_val = int(status_str)
            except ValueError:
                pass

        # Severity mapping
        severity = get_field_val(norm_row, ["severity", "level", "log_level"]).lower()
        if not severity:
            if status_val and 500 <= status_val <= 599:
                severity = "error"
            elif status_val and 400 <= status_val <= 499:
                severity = "warn"
            else:
                severity = "info"

        # Raw message mapping
        raw_msg = get_field_val(norm_row, ["raw_message", "message", "msg", "log", "description"])
        if not raw_msg:
            # Synthesize informative raw message from row components if none explicitly provided
            components = [f"{k}: {v}" for k, v in row.items() if v]
            raw_msg = " | ".join(components)

        # Validation rules
        errors = []
        parsed_dt = None
        if not raw_ts:
            errors.append("Missing required field: timestamp")
        else:
            parsed_dt = parse_timestamp(raw_ts)
            if not parsed_dt:
                errors.append(f"Malformed timestamp format: '{raw_ts}'")
        
        if not source:
            errors.append("Missing required field: source")

        if errors:
            rejected_count += 1
            error_reason = "; ".join(errors)
            if len(rejection_details) < 200:  # Cap details in DB to keep payload compact
                rejection_details.append({
                    "row_index": idx,
                    "raw_id": raw_id,
                    "raw_timestamp": raw_ts,
                    "source": source,
                    "reason": error_reason
                })
            entries_to_add.append(LogEntry(
                raw_id=raw_id,
                raw_timestamp=raw_ts,
                timestamp=None,
                source=source,
                event_type=event_type,
                severity=severity,
                status=status_val,
                raw_message=raw_msg,
                is_valid=False,
                validation_error=error_reason
            ))
        else:
            valid_count += 1
            entries_to_add.append(LogEntry(
                raw_id=raw_id,
                raw_timestamp=raw_ts,
                timestamp=parsed_dt,
                source=source,
                event_type=event_type,
                severity=severity,
                status=status_val,
                raw_message=raw_msg,
                is_valid=True,
                validation_error=None
            ))

    # Fast bulk insert in batches of 5,000
    batch_size = 5000
    for i in range(0, len(entries_to_add), batch_size):
        db.bulk_save_objects(entries_to_add[i:i + batch_size])
        db.commit()

    summary = IngestionSummary(
        filename=filename,
        total_rows=total,
        valid_rows=valid_count,
        rejected_rows=rejected_count,
        flagged_rows=0,
        rejection_details=json.dumps(rejection_details)
    )
    db.add(summary)
    db.commit()
    db.refresh(summary)
    return summary
