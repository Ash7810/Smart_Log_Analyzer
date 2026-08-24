import json
import os
from typing import Optional, List
from fastapi import FastAPI, Depends, UploadFile, File, Form, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.db import init_db, get_db, LogEntry, FlaggedEntry, IngestionSummary
from backend.ingestion import validate_and_ingest_csv
from backend.detector import run_anomaly_detection
from backend.ai import generate_explanation_and_root_cause

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(
    title="Smart Log Analyzer & Anomaly Detector API",
    description="Deterministic rule-based anomaly detection with Gemini-powered explanations and full ingestion validation",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Static Frontend mounting
static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.api_route("/", methods=["GET", "HEAD"])
def serve_index():
    index_file = os.path.join(static_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"status": "ok", "service": "LogPulse API"}

@app.api_route("/api/health", methods=["GET", "HEAD"])
def health_check():
    return {"status": "ok", "service": "LogPulse API"}

@app.post("/api/clear")
def clear_database(db: Session = Depends(get_db)):
    """
    Clears all logs, flagged entries, and ingestion summaries from the database.
    """
    db.query(FlaggedEntry).delete()
    db.query(LogEntry).delete()
    db.query(IngestionSummary).delete()
    db.commit()
    return {"status": "success", "message": "Database cleared successfully"}

@app.post("/api/ingest-default")
def ingest_default_dataset(db: Session = Depends(get_db)):
    """
    Loads and validates the default sample logs.csv from workspace root.
    """
    root_dir = os.path.dirname(os.path.dirname(__file__))
    default_csv_path = os.path.join(root_dir, "logs.csv")
    if not os.path.exists(default_csv_path):
        raise HTTPException(status_code=404, detail="Default logs.csv not found on server")
    
    with open(default_csv_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    summary = validate_and_ingest_csv(db, content, "logs.csv")
    flagged = run_anomaly_detection(db)
    return {
        "status": "success",
        "summary": {
            "id": summary.id,
            "filename": summary.filename,
            "total_rows": summary.total_rows,
            "valid_rows": summary.valid_rows,
            "rejected_rows": summary.rejected_rows,
            "flagged_rows": len(flagged),
            "rejections": json.loads(summary.rejection_details) if summary.rejection_details else []
        }
    }

@app.post("/api/ingest")
async def ingest_logs(
    file: Optional[UploadFile] = File(None),
    raw_csv: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    """
    Ingest a CSV file or raw CSV text string, validate structure and timestamps.
    """
    content = ""
    filename = "logs.csv"

    if file:
        filename = file.filename
        content_bytes = await file.read()
        content = content_bytes.decode("utf-8", errors="replace")
    elif raw_csv is not None:
        content = raw_csv
    else:
        raise HTTPException(status_code=400, detail="No file or CSV text provided")

    summary = validate_and_ingest_csv(db, content, filename)
    # Automatically run anomaly detection after ingestion
    flagged = run_anomaly_detection(db)

    return {
        "status": "success",
        "summary": {
            "id": summary.id,
            "filename": summary.filename,
            "total_rows": summary.total_rows,
            "valid_rows": summary.valid_rows,
            "rejected_rows": summary.rejected_rows,
            "flagged_rows": len(flagged),
            "rejections": json.loads(summary.rejection_details or "[]")
        }
    }

@app.get("/api/summary")
def get_summary(db: Session = Depends(get_db)):
    summary = db.query(IngestionSummary).order_by(IngestionSummary.id.desc()).first()
    if not summary:
        return {
            "filename": "None",
            "total_rows": 0,
            "valid_rows": 0,
            "rejected_rows": 0,
            "flagged_rows": 0,
            "rejections": []
        }
    return {
        "id": summary.id,
        "filename": summary.filename,
        "total_rows": summary.total_rows,
        "valid_rows": summary.valid_rows,
        "rejected_rows": summary.rejected_rows,
        "flagged_rows": summary.flagged_rows,
        "rejections": json.loads(summary.rejection_details or "[]"),
        "timestamp": summary.timestamp.isoformat() if summary.timestamp else None
    }

@app.get("/api/logs")
def get_logs(
    only_flagged: bool = False,
    only_invalid: bool = False,
    severity: Optional[str] = None,
    rule: Optional[str] = None,
    limit: int = 500,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    query = db.query(LogEntry)
    if only_invalid:
        query = query.filter(LogEntry.is_valid == False)
    elif only_flagged:
        query = query.join(FlaggedEntry, LogEntry.id == FlaggedEntry.log_entry_id)
        if rule:
            query = query.filter(FlaggedEntry.detector_rule == rule)

    if severity:
        query = query.filter(LogEntry.severity == severity.lower())

    # Order invalid to the end or keep chronological
    total_count = query.count()
    entries = query.order_by(LogEntry.id.asc()).offset(offset).limit(limit).all()

    results = []
    for entry in entries:
        flagged_data = None
        if entry.flagged_entry:
            flagged_data = {
                "id": entry.flagged_entry.id,
                "detector_rule": entry.flagged_entry.detector_rule,
                "score": entry.flagged_entry.score,
                "reason": entry.flagged_entry.reason,
                "ai_explanation": entry.flagged_entry.ai_explanation,
                "ai_root_cause": entry.flagged_entry.ai_root_cause,
                "created_at": entry.flagged_entry.created_at.isoformat() if entry.flagged_entry.created_at else None
            }

        results.append({
            "id": entry.id,
            "raw_id": entry.raw_id,
            "timestamp": entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if entry.timestamp else entry.raw_timestamp,
            "source": entry.source,
            "event_type": entry.event_type,
            "severity": entry.severity,
            "status": entry.status,
            "raw_message": entry.raw_message,
            "is_valid": entry.is_valid,
            "validation_error": entry.validation_error,
            "is_flagged": flagged_data is not None,
            "flagged": flagged_data
        })

    return {"total": total_count, "items": results}

@app.get("/api/flagged")
def get_flagged_entries(db: Session = Depends(get_db)):
    flagged = db.query(FlaggedEntry).join(LogEntry).order_by(LogEntry.timestamp.asc()).all()
    results = []
    for f in flagged:
        entry = f.log_entry
        results.append({
            "flagged_id": f.id,
            "log_entry_id": entry.id,
            "raw_id": entry.raw_id,
            "timestamp": entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if entry.timestamp else entry.raw_timestamp,
            "source": entry.source,
            "event_type": entry.event_type,
            "severity": entry.severity,
            "status": entry.status,
            "raw_message": entry.raw_message,
            "detector_rule": f.detector_rule,
            "score": f.score,
            "reason": f.reason,
            "ai_explanation": f.ai_explanation,
            "ai_root_cause": f.ai_root_cause
        })
    return {"total": len(results), "items": results}

@app.post("/api/explain/{flagged_id}")
def explain_flagged_entry(flagged_id: int, force_refresh: bool = False, db: Session = Depends(get_db)):
    """
    Generates and caches AI explanation and remediation plan for a specific flagged entry.
    """
    flagged = db.query(FlaggedEntry).filter(FlaggedEntry.id == flagged_id).first()
    if not flagged:
        raise HTTPException(status_code=404, detail="Flagged entry not found")

    # If already cached and valid and not force refreshing, return existing
    if not force_refresh and flagged.ai_explanation and not flagged.ai_explanation.startswith("Explanation unavailable"):
        return {
            "flagged_id": flagged.id,
            "cached": True,
            "ai_explanation": flagged.ai_explanation,
            "ai_root_cause": flagged.ai_root_cause
        }

    entry = flagged.log_entry
    explanation, root_cause = generate_explanation_and_root_cause(
        entry_id=entry.raw_id or entry.id,
        timestamp=entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if entry.timestamp else str(entry.raw_timestamp),
        source=entry.source or "unknown",
        event_type=entry.event_type or "unknown",
        severity=entry.severity or "unknown",
        raw_message=entry.raw_message or "",
        detector_rule=flagged.detector_rule,
        score_or_reason=flagged.reason
    )

    flagged.ai_explanation = explanation
    flagged.ai_root_cause = root_cause
    db.commit()

    return {
        "flagged_id": flagged.id,
        "cached": False,
        "ai_explanation": flagged.ai_explanation,
        "ai_root_cause": flagged.ai_root_cause
    }

from concurrent.futures import ThreadPoolExecutor, as_completed

@app.post("/api/explain-all")
def explain_all_flagged(force_refresh: bool = False, db: Session = Depends(get_db)):
    """
    Batch generate and cache AI explanations and remediation plans for flagged entries concurrently.
    """
    flagged_list = db.query(FlaggedEntry).all()
    if force_refresh:
        to_explain = flagged_list
    else:
        to_explain = [
            f for f in flagged_list
            if not f.ai_explanation or f.ai_explanation.startswith("Explanation unavailable")
        ]
    
    if not to_explain:
        return {"status": "success", "generated_count": 0, "total_flagged": len(flagged_list)}

    def process_entry(flagged_id, raw_id, fallback_id, ts, source, event_type, severity, raw_msg, rule, reason):
        explanation, root_cause = generate_explanation_and_root_cause(
            entry_id=raw_id or fallback_id,
            timestamp=ts,
            source=source or "unknown",
            event_type=event_type or "unknown",
            severity=severity or "unknown",
            raw_message=raw_msg or "",
            detector_rule=rule,
            score_or_reason=reason
        )
        return flagged_id, explanation, root_cause

    # Run up to 8 parallel requests to Gemini
    tasks = []
    with ThreadPoolExecutor(max_workers=8) as executor:
        for f in to_explain:
            entry = f.log_entry
            ts_str = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if entry.timestamp else str(entry.raw_timestamp)
            tasks.append(executor.submit(
                process_entry,
                f.id,
                entry.raw_id,
                entry.id,
                ts_str,
                entry.source,
                entry.event_type,
                entry.severity,
                entry.raw_message,
                f.detector_rule,
                f.reason
            ))

        results_map = {}
        for future in as_completed(tasks):
            try:
                fid, exp, rc = future.result()
                results_map[fid] = (exp, rc)
            except Exception:
                pass

    count_generated = 0
    for f in flagged_list:
        if f.id in results_map:
            f.ai_explanation, f.ai_root_cause = results_map[f.id]
            count_generated += 1

    db.commit()
    return {"status": "success", "generated_count": count_generated, "total_flagged": len(flagged_list)}
