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


def deterministic_assessment(clause_text, evidence_texts):
    """Conservative local checks extracted from the supplied clause text itself."""
    evidence = " ".join(evidence_texts)
    labels = []
    for label in re.findall(r"(?:\([a-z]\)\s*)?([A-Z][A-Za-z /-]{2,60})(?::|\s*\()", clause_text):
        clean = " ".join(label.split()).strip(" -/")
        if clean.lower() not in {item.lower() for item in labels} and len(clean.split()) <= 8:
            labels.append(clean)
    missing = [label for label in labels if not re.search(re.escape(label), evidence, re.I)]
    matched = [label for label in labels if label not in missing]
    gaps = [f"No evidence found for required named role/item: {label}." for label in missing]
    lower_clause, lower_evidence = clause_text.lower(), evidence.lower()
    if any(term in lower_clause for term in ("annually", "annual", "once a year", "every year")) and not any(term in lower_evidence for term in ("annually", "annual", "yearly", "once a year", "2024", "2025", "2026")):
        gaps.append("Annual recurrence or dated yearly execution evidence was not found.")
    if any(term in lower_clause for term in ("approve", "approved")) and not any(term in lower_evidence for term in ("approved", "approval", "signed", "signature")):
        gaps.append("Approval or signature evidence was not found.")
    if not evidence_texts:
        status = "INSUFFICIENT_EVIDENCE"
    elif labels and len(missing) == len(labels):
        status = "NON_COMPLIANT"
    elif gaps:
        status = "PARTIAL"
    else:
        status = "INSUFFICIENT_EVIDENCE"
    return {"status": status, "summary": "Local deterministic checks completed against the active evidence set.", "matched": matched, "gaps": gaps, "next_evidence": [gap.replace("No evidence found for required named role/item: ", "Provide documented evidence for ") for gap in gaps], "engine": "LOCAL_RULES"}


def analyze_clause(*, clause_text, evidence_texts):
    local = deterministic_assessment(clause_text, evidence_texts)
    key = os.getenv("GEMINI_API_KEY")
    if not key:
        return local
    if not evidence_texts:
        return local
    prompt = {
        "task": "Return a preliminary evidence-sufficiency assessment only. Do not claim legal certification.",
        "allowed_statuses": ["COMPLIANT", "PARTIAL", "NON_COMPLIANT", "INSUFFICIENT_EVIDENCE"],
        "clause": redact(clause_text), "evidence": [redact(item) for item in evidence_texts], "local_checks": local,
        "output_json": {"status": "one allowed status", "summary": "brief", "matched": ["source-supported point"], "gaps": ["missing proof"], "next_evidence": ["specific requested proof"]},
    }
    model = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
    request = Request(f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}", data=json.dumps({"contents": [{"parts": [{"text": json.dumps(prompt)}]}], "generationConfig": {"responseMimeType": "application/json", "temperature": 0}}).encode(), headers={"Content-Type": "application/json"})
    try:
        with urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode())
        result = json.loads(payload["candidates"][0]["content"]["parts"][0]["text"])
    except (HTTPError, URLError, TimeoutError, KeyError, IndexError, json.JSONDecodeError) as exc:
        local["summary"] += " Semantic AI review was unavailable; status is based on local checks."
        return local
    if result.get("status") not in {"COMPLIANT", "PARTIAL", "NON_COMPLIANT", "INSUFFICIENT_EVIDENCE"}:
        raise ValidationError("AI returned an invalid assessment state.")
    result["engine"] = "HYBRID_LOCAL_GEMINI"
    result["local_checks"] = local
    if local["status"] == "NON_COMPLIANT" and result["status"] == "COMPLIANT":
        result["status"] = "PARTIAL"
        result.setdefault("gaps", []).extend(local["gaps"])
    return result
