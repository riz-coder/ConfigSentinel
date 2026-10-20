"""Redaction-first Gemini adapter for preliminary evidence findings."""
import json
import os
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from django.core.exceptions import ValidationError

REDACTIONS = (
    (re.compile(r"\b\d{5}-\d{7}-\d\b"), "[REDACTED_ID]"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[REDACTED_IP]"),
    (re.compile(r"(?i)\b(?:api[_ -]?key|password|secret|token)\s*[:=]\s*\S+"), "[REDACTED_SECRET]"),
    (re.compile(r"\b(?:\+92|0)3\d{9}\b"), "[REDACTED_PHONE]"),
)


def redact(text):
    for pattern, replacement in REDACTIONS:
        text = pattern.sub(replacement, text)
    return text[:24000]


def analyze_clause(*, clause_text, evidence_texts):
    key = os.getenv("GEMINI_API_KEY")
    if not key:
        raise ValidationError("AI assessment is not configured.")
    if not evidence_texts:
        return {"status": "INSUFFICIENT_EVIDENCE", "summary": "No text-readable evidence was available.", "gaps": ["Upload a text-readable PDF, DOCX, XLSX, CSV, or TXT file."], "next_evidence": []}
    prompt = {
        "task": "Return a preliminary evidence-sufficiency assessment only. Do not claim legal certification.",
        "allowed_statuses": ["COMPLIANT", "PARTIAL", "NON_COMPLIANT", "INSUFFICIENT_EVIDENCE"],
        "clause": redact(clause_text), "evidence": [redact(item) for item in evidence_texts],
        "output_json": {"status": "one allowed status", "summary": "brief", "matched": ["source-supported point"], "gaps": ["missing proof"], "next_evidence": ["specific requested proof"]},
    }
    model = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
    request = Request(f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}", data=json.dumps({"contents": [{"parts": [{"text": json.dumps(prompt)}]}], "generationConfig": {"responseMimeType": "application/json", "temperature": 0}}).encode(), headers={"Content-Type": "application/json"})
    try:
        with urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode())
        result = json.loads(payload["candidates"][0]["content"]["parts"][0]["text"])
    except (HTTPError, URLError, TimeoutError, KeyError, IndexError, json.JSONDecodeError) as exc:
        raise ValidationError("AI assessment could not be completed; no finding was recorded.") from exc
    if result.get("status") not in {"COMPLIANT", "PARTIAL", "NON_COMPLIANT", "INSUFFICIENT_EVIDENCE"}:
        raise ValidationError("AI returned an invalid assessment state.")
    return result
