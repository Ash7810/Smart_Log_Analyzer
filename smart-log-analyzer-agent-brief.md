# Task Brief: Smart Log Analyzer & Anomaly Detector

Build a working MVP. Follow the constraints below exactly — do not substitute stack choices or expand scope beyond what's listed.

## Hard Constraints

- Backend: Python + FastAPI
- DB: SQLite (SQLAlchemy or raw sqlite3, either is fine)
- Frontend: Streamlit
- AI: Gemini API, called ONLY to generate explanations for entries already flagged by rule-based logic — never to decide what counts as anomalous
- No auth, no multi-user, no real-time streaming, no ML model training
- AI-generated explanations must be cached in the DB, not regenerated on every page load
- AI API failures must degrade gracefully ("explanation unavailable"), never crash the view

## Data Model

```
LogEntry: id, timestamp (required), source (required), event_type, severity, raw_message, is_valid
FlaggedEntry: id, log_entry_id (fk), score/reason, detector_rule, ai_explanation, ai_root_cause, created_at
```

## Task Sequence

1. **Dataset**: synthesize a synthetic log dataset (dozens–low hundreds of rows), mostly-normal entries plus a handful of deliberate anomalies (severity spikes, request bursts from one source, rare event types, off-hours access to sensitive paths). Do not copy the sample table from the problem statement verbatim.

2. **Ingestion + validation**: load dataset into SQLite. Reject rows with missing timestamp or malformed structure; continue processing the rest. Handle empty dataset without crashing. Track a validation summary (rows loaded vs rejected + reason).

3. **Anomaly detector** (own logic, no AI): implement 2–3 of the following, not all five —
   - severity-based (5xx / error / critical auto-flags)
   - frequency/burst detection (z-score or threshold on requests-per-source-per-minute)
   - rare event type (event types below a frequency threshold)
   - off-pattern access (sensitive paths, odd-hour timestamps)
   Persist detector_rule name + score/reason per flag.

4. **AI explanation**: for each FlaggedEntry, call Gemini API with the entry's fields + detector_rule + score. Prompt should ask for a 2-3 sentence plain-English explanation plus a likely root cause / next step. Cache result in ai_explanation / ai_root_cause fields.

5. **Frontend (Streamlit)**:
   - List/timeline view: all entries, flagged ones visually highlighted
   - Detail view: full entry + detector reason/score + AI explanation + root cause
   - Validation summary visible somewhere (e.g. "48 loaded, 2 rejected")

6. **README**: setup instructions (env vars for Gemini key, how to run), detector approach + reasoning, AI usage + reasoning, assumptions made, known limitations.

## Do Not

- Do not let the AI component influence which entries get flagged
- Do not add authentication, dashboards beyond the list/detail views, or a different frontend framework
- Do not regenerate AI explanations on each page view
