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


def deterministic_assessment(clause_text, evidence_texts=None, evidence_documents=None):
    """Conservative proof checks; keyword presence alone is never treated as proof."""
    documents = evidence_documents or [{"filename": "evidence", "text": text, "embedded_images": 0} for text in (evidence_texts or [])]
    readable = [doc for doc in documents if len(doc.get("text", "").strip()) >= 40]
    evidence = " ".join(doc.get("text", "") for doc in readable)
    labels = []
    for label in re.findall(r"(?:\([a-z]\)\s*)?([A-Z][A-Za-z /-]{2,60})(?::|\s*\()", clause_text):
        clean = " ".join(label.split()).strip(" -/")
        if clean.lower() not in {item.lower() for item in labels} and len(clean.split()) <= 8:
            labels.append(clean)
    responsibility_terms = r"responsib|accountab|approv|review|report|implement|maintain|conduct|assign|shall|must"
    supported, missing = [], []
    for label in labels:
        # A label is supported only when it appears near an action/responsibility,
        # preventing a pasted list of clause keywords from passing the check.
        linked = re.search(rf"(?:{re.escape(label)}.{{0,180}}(?:{responsibility_terms})|(?:{responsibility_terms}).{{0,180}}{re.escape(label)})", evidence, re.I | re.S)
        (supported if linked else missing).append(label)
    matched = [f"Named role/item linked to an action in readable evidence: {label}." for label in supported]
    gaps = [f"No action-linked evidence found for required named role/item: {label}." for label in missing]
    checks = [{"requirement": label, "status": "PROVEN" if label in supported else "MISSING"} for label in labels]
    lower_clause, lower_evidence = clause_text.lower(), evidence.lower()
    if any(term in lower_clause for term in ("annually", "annual", "once a year", "every year")) and not re.search(r"\b(?:20\d{2}|annual(?:ly)?|yearly)\b", lower_evidence):
        gaps.append("Annual recurrence or dated yearly execution evidence was not found.")
        checks.append({"requirement": "Annual recurrence", "status": "MISSING"})
    elif any(term in lower_clause for term in ("annually", "annual", "once a year", "every year")):
        matched.append("A dated/annual reference was found; recurrence still requires reviewer validation.")
        checks.append({"requirement": "Annual recurrence", "status": "PARTIAL"})
    if any(term in lower_clause for term in ("approve", "approved")) and not any(term in lower_evidence for term in ("approved", "approval", "signed", "signature")):
        gaps.append("Approval or signature evidence was not found.")
        checks.append({"requirement": "Approval/signature", "status": "MISSING"})
    elif any(term in lower_clause for term in ("approve", "approved")):
        matched.append("Approval/signature wording was found; authenticity requires reviewer validation.")
        checks.append({"requirement": "Approval/signature", "status": "PARTIAL"})
    unreadable = [doc["filename"] for doc in documents if len(doc.get("text", "").strip()) < 40]
    image_only = [doc["filename"] for doc in documents if doc.get("embedded_images", 0) and len(doc.get("text", "").strip()) < 40]
    if unreadable:
        gaps.append("Unreadable or non-text evidence requires OCR/manual visual review: " + ", ".join(unreadable) + ".")
        checks.append({"requirement": "Machine-readable content", "status": "UNREADABLE"})
    if image_only:
        gaps.append("Embedded pictures are supporting material only and do not prove dates, approvals, attendance completeness, or recurrence.")
    tokens = re.findall(r"[a-z]{3,}", lower_evidence)
    if len(tokens) >= 30 and len(set(tokens)) / len(tokens) < 0.22:
        gaps.append("Evidence has unusually repetitive text and requires manual review for keyword stuffing or copied content.")
        checks.append({"requirement": "Content integrity", "status": "CONTRADICTED"})
    if not documents:
        status = "INSUFFICIENT_EVIDENCE"
    elif not readable:
        status = "INSUFFICIENT_EVIDENCE"
    elif labels and len(missing) == len(labels):
        status = "NON_COMPLIANT"
    elif gaps:
        status = "PARTIAL"
    else:
        # Local automation cannot authenticate a document or approve evidence.
        status = "PARTIAL"
        gaps.append("Automated checks found no obvious gap, but document authenticity and operating effectiveness require human review.")
    return {"status": status, "summary": "Structured local proof checks completed against active evidence; keywords alone do not count as proof.", "matched": matched, "gaps": gaps, "next_evidence": gaps, "requirement_checks": checks, "engine": "LOCAL_RULES_V2"}


def analyze_clause(*, clause_text, evidence_texts=None, evidence_documents=None):
    local = deterministic_assessment(clause_text, evidence_texts, evidence_documents)
    gemini_enabled = os.getenv("GEMINI_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}
    if not gemini_enabled:
        local["summary"] += " External semantic AI review is paused."
        return local
    key = os.getenv("GEMINI_API_KEY")
    if not key:
        return local
    if not (evidence_documents or evidence_texts):
        return local
    prompt = {
        "task": "Return a preliminary evidence-sufficiency assessment only. Do not claim legal certification.",
        "allowed_statuses": ["COMPLIANT", "PARTIAL", "NON_COMPLIANT", "INSUFFICIENT_EVIDENCE"],
        "clause": redact(clause_text), "evidence": [redact(doc.get("text", "")) for doc in evidence_documents] if evidence_documents else [redact(item) for item in evidence_texts], "local_checks": local,
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
