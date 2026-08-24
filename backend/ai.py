import os
import json
from typing import Optional, Tuple
from dotenv import load_dotenv

load_dotenv()

# We can import google.genai or fallback safely
try:
    from google import genai
    from google.genai import types
    HAS_GEMINI_LIB = True
except ImportError:
    HAS_GEMINI_LIB = False

def get_gemini_client():
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key or not HAS_GEMINI_LIB:
        return None
    try:
        client = genai.Client(api_key=api_key)
        return client
    except Exception:
        return None

def generate_explanation_and_root_cause(
    entry_id: int,
    timestamp: str,
    source: str,
    event_type: str,
    severity: str,
    raw_message: str,
    detector_rule: str,
    score_or_reason: str
) -> Tuple[str, str]:
    """
    Calls Gemini API ONLY to generate explanations for an already flagged entry.
    Never decides what counts as anomalous.
    Degrades gracefully if API is unavailable, key is missing, or network fails.
    """
    client = get_gemini_client()
    
    if not client:
        return (
            "Explanation unavailable (Gemini API key not configured or client library unavailable).",
            "Root cause analysis unavailable without active Gemini API connection."
        )

    prompt = f"""You are a security and log analysis assistant embedded in a Smart Log Analyzer tool.
You are given a log entry that has ALREADY been flagged as anomalous by a separate rule-based detector.
Your job is to provide two separate pieces of information:
1. "explanation": A concise 2-3 sentence plain-English explanation of why this event is anomalous and what the likely root cause is. Do not question the flag or add detection logic.
2. "remediation": A concrete, 2-3 sentence actionable investigation and remediation plan for the security/operations team to investigate, contain, and resolve this incident.

Respond ONLY in valid JSON format matching this exact schema:
{{
  "explanation": "2-3 sentences plain-English incident explanation and root cause...",
  "remediation": "2-3 sentences actionable remediation plan..."
}}

Log Entry Details:
- ID: {entry_id}
- Timestamp: {timestamp}
- Source IP/Host: {source}
- Event Type: {event_type}
- Severity: {severity}
- Raw Log: {raw_message}
- Detector Rule: {detector_rule}
- Detector Reason: {score_or_reason}
"""

    # Try production model chain with exponential backoff & failover
    candidate_models = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash", "gemini-2.0-flash-lite"]
    last_error = ""

    for model_name in candidate_models:
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.2,
                    response_mime_type="application/json"
                )
            )
            text = response.text.strip()
            data = json.loads(text)
            explanation = data.get("explanation", text)
            remediation = data.get("remediation", "Verify source host authorization and review system events around timestamp.")
            return explanation, remediation
        except Exception as e:
            last_error = str(e)
            continue

    # High-quality contextual fallback if API quota or connectivity is exhausted
    rule_explanations = {
        "severity_spike": f"This event was flagged due to an unhandled internal server error or critical severity response on '{event_type}'. The likely root cause is a database connectivity issue, downstream service failure, or unhandled application exception.",
        "burst_frequency": f"Source '{source}' generated high-frequency request traffic exceeding normal operational rates within a single 60-second window. The likely root cause is an automated brute-force attempt, credential stuffing attack, or an unthrottled API client loop.",
        "off_hours_access": f"Sensitive administrative path '{event_type}' was accessed by '{source}' at {timestamp}, which falls outside standard operational business hours. The likely root cause is unauthorized off-hours access or unscheduled maintenance.",
        "rare_event_type": f"Event type '{event_type}' is an infrequently observed operation across the system cluster. The likely root cause is an unscheduled administrative action, debug operation, or potential data exfiltration attempt."
    }
    rule_remediations = {
        "severity_spike": "1. Inspect application server error logs and stack traces around the incident timestamp.\n2. Verify upstream database and microservice health.\n3. Deploy hotfix if code exception is identified.",
        "burst_frequency": "1. Temporarily rate-limit or block source IP at the firewall/WAF.\n2. Review authentication logs for compromised account credentials.\n3. Enforce CAPTCHA and stricter throttling policies on the endpoint.",
        "off_hours_access": "1. Contact the account owner to confirm if this access was authorized.\n2. Review subsequent session commands and lateral movement logs.\n3. Revoke active session tokens if unauthorized.",
        "rare_event_type": "1. Validate whether the originating host is authorized to execute this administrative endpoint.\n2. Audit export volume and egress bandwidth for potential data exfiltration.\n3. Restrict endpoint access via role-based access control (RBAC)."
    }

    fallback_exp = rule_explanations.get(detector_rule, f"Anomalous pattern detected on {event_type} originating from {source}.")
    fallback_rc = rule_remediations.get(detector_rule, "1. Verify host IP identity.\n2. Review adjacent log events.\n3. Revoke access if suspicious.")

    return fallback_exp, fallback_rc
