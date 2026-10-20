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

STOPWORDS = {
    "about", "after", "against", "also", "and", "any", "are", "been", "being", "but", "for",
    "from", "has", "have", "into", "its", "may", "must", "not", "of", "on", "or", "shall",
    "should", "such", "that", "the", "their", "these", "this", "to", "under", "which", "with",
}


def _keywords(text):
    return {word for word in re.findall(r"[a-z]{4,}", text.lower()) if word not in STOPWORDS}


def _source_requirement_topics(clause_text):
    """Return exact, compact source-derived requirement fragments without inventing obligations."""
    normalized = re.sub(r"\r", "", clause_text)
    marker = re.compile(r"(?:^|\n)\s*\((?:\d+|[a-z]|[ivx]+)\)\s+", re.I)
    starts = list(marker.finditer(normalized))
    topics = []
    for index, match in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(normalized)
        fragment = " ".join(normalized[match.end():end].split())
        if 15 <= len(fragment) <= 600:
            topics.append(fragment[:220])
    if not topics:
        for sentence in re.split(r"(?<=[.;])\s+|\n+", normalized):
            compact = " ".join(sentence.split())
            if 15 <= len(compact) <= 600 and re.search(r"\b(?:shall|must|required|ensure|maintain|establish|develop|formulate)\b", compact, re.I):
                topics.append(compact[:220])
    unique = []
    for topic in topics:
        if topic.lower() not in {item.lower() for item in unique}:
            unique.append(topic)
    return unique[:20]


def _document_requirement_assessment(clause_text, documents):
    lower_clause = clause_text.lower()
    kinds = [kind for kind in ("policy", "procedure", "plan", "programme", "program", "framework", "sop") if re.search(rf"\b{kind}(?:s)?\b", lower_clause)]
    if not kinds:
        return None
    readable = [doc for doc in documents if len(doc.get("text", "").strip()) >= 40]
    candidates = []
    for doc in readable:
        identity = f"{doc.get('filename', '')} {doc.get('text', '')[:1500]}".lower()
        if any(re.search(rf"\b{re.escape(kind)}(?:s)?\b", identity) for kind in kinds):
            candidates.append(doc)
    required_label = "/".join(kinds)
    topics = _source_requirement_topics(clause_text)
    if not candidates:
        return {
            "required_type": required_label,
            "status": "MISSING",
            "documents": [],
            "governance": [],
            "coverage": [{"source_requirement": topic, "status": "MISSING"} for topic in topics],
        }
    combined = " ".join(doc.get("text", "") for doc in candidates)
    lower = combined.lower()
    governance_patterns = (
        ("Document purpose", r"\bpurpose\b"),
        ("Scope", r"\bscope\b"),
        ("Owner/responsibility", r"\b(?:owner|responsib|accountab)"),
        ("Approval/signature", r"\b(?:approv|signature|signed by)"),
        ("Version/document control", r"\b(?:version|revision|document control)\b"),
        ("Effective/review date", r"\b(?:effective date|review date|next review|20\d{2})\b"),
    )
    governance = [{"item": name, "status": "PRESENT" if re.search(pattern, lower, re.I) else "MISSING"} for name, pattern in governance_patterns]
    coverage = []
    for topic in topics:
        topic_words = _keywords(topic)
        overlap = topic_words & _keywords(combined)
        threshold = min(3, max(1, len(topic_words) // 2))
        status = "POTENTIALLY_COVERED" if len(overlap) >= threshold else "MISSING"
        coverage.append({"source_requirement": topic, "status": status})
    has_missing = any(item["status"] == "MISSING" for item in governance + coverage)
    return {
        "required_type": required_label,
        "status": "PARTIAL" if has_missing else "PRESENT_UNVERIFIED",
        "documents": [doc.get("filename", "evidence") for doc in candidates],
        "governance": governance,
        "coverage": coverage,
    }


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
    # Named roles/items must be explicit labels ending in a colon. A capitalized
    # phrase before a number, e.g. "Authority within twenty-four (24)", is prose.
    for label in re.findall(r"(?:^|[\n.;])\s*(?:\([a-z0-9]+\)\s*)?([A-Z][A-Za-z /&-]{2,60})\s*:", clause_text, re.M):
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
    document_requirement = _document_requirement_assessment(clause_text, documents)
    if document_requirement:
        required_type = document_requirement["required_type"]
        if document_requirement["status"] == "MISSING":
            gaps.append(f"Documented {required_type} is missing; no readable active file was identified as the required controlled document.")
            checks.append({"requirement": f"Documented {required_type}", "status": "MISSING"})
        else:
            matched.append(f"Required document type is present for preliminary review: {', '.join(document_requirement['documents'])}.")
            checks.append({"requirement": f"Documented {required_type}", "status": document_requirement["status"]})
            for item in document_requirement["governance"]:
                if item["status"] == "MISSING":
                    gaps.append(f"Document-control field missing from the submitted {required_type}: {item['item']}.")
            missing_topics = [item["source_requirement"] for item in document_requirement["coverage"] if item["status"] == "MISSING"]
            for topic in missing_topics:
                gaps.append(f"Submitted {required_type} does not show coverage of this source-derived requirement: {topic}")
    if any(term in lower_clause for term in ("report", "notify", "notification", "escalat")):
        reporting_proof = re.search(r"\b(?:report(?:ed|ing)?|notif(?:y|ied|ication)|escalat(?:e|ed|ion))\b.{0,180}\b(?:incident|authority|team|register|ticket|reference|timestamp)\b", lower_evidence, re.S)
        if reporting_proof:
            matched.append("Incident reporting/escalation language is linked to an operational record or responsible party.")
            checks.append({"requirement": "Reporting/escalation process", "status": "PARTIAL"})
        else:
            gaps.append("No action-linked incident reporting/escalation procedure or record was found.")
            checks.append({"requirement": "Reporting/escalation process", "status": "MISSING"})
    deadlines = sorted(set(re.findall(r"\b(\d{1,3})\s*\)?\s*(?:hours?|hrs?|days?)\b", lower_clause)))
    for deadline in deadlines:
        if re.search(rf"\b{re.escape(deadline)}\s*(?:hours?|hrs?|days?)\b", lower_evidence):
            matched.append(f"The evidence mentions the source deadline value ({deadline}); execution timestamps still require reviewer validation.")
            checks.append({"requirement": f"Deadline {deadline}", "status": "PARTIAL"})
        else:
            gaps.append(f"Evidence does not show the source deadline value ({deadline}) with an hours/days unit.")
            checks.append({"requirement": f"Deadline {deadline}", "status": "MISSING"})
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
    observations = [
        {
            "filename": doc.get("filename", "evidence"),
            "extracted_characters": len(doc.get("text", "").strip()),
            "embedded_images": doc.get("embedded_images", 0),
            "ocr_used": bool(doc.get("ocr_used")),
            "ocr_confidence": doc.get("ocr_confidence"),
            "readability": "READABLE" if len(doc.get("text", "").strip()) >= 40 else "UNREADABLE_OR_IMAGE_ONLY",
        }
        for doc in documents
    ]
    return {"status": status, "summary": "Structured local proof checks completed against active evidence; keywords alone do not count as proof.", "matched": matched, "gaps": gaps, "next_evidence": gaps, "requirement_checks": checks, "document_requirement": document_requirement, "document_observations": observations, "engine": "LOCAL_RULES_V2"}


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
