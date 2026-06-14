"""Findings API — vulnerability findings CRUD with deduplication + ML severity prediction"""
import re
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.security import require_viewer, require_analyst
from app.db.session import get_db
from app.models.models import AuditLog, Finding, Scan
from app.ml.severity_predictor import predict_severity, batch_predict

router = APIRouter()


def _enum_val(v) -> str:
    """Safely convert enum or string to string."""
    return v.value if hasattr(v, "value") else str(v)


def _finding_dict(f: Finding) -> dict:
    return {
        "id":                 f.id,
        "scan_id":            f.scan_id,
        "owasp_category":     f.owasp_category,
        "owasp_name":         f.owasp_name,
        "title":              f.title,
        "description":        f.description,
        "severity":           _enum_val(f.severity),
        "status":             _enum_val(f.status),
        "affected_url":       f.affected_url,
        "affected_parameter": f.affected_parameter,
        "http_method":        f.http_method,
        "risk_score":         f.risk_score,
        "cvss_score":         f.cvss_score,
        "confidence":         f.confidence,
        "evidence":           f.evidence,
        "remediation":        f.remediation,
        "references":         f.references,
        "is_false_positive":  f.is_false_positive,
        "detected_at":        f.detected_at,
    }


# ── Deduplication helpers ──────────────────────────────────────────────────────

_SAST_DAST_PREFIX = re.compile(r"^\[(SAST|DAST)\]\s*", re.IGNORECASE)

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _normalize_title(title: str) -> str:
    """Strip [SAST]/[DAST] prefix so identical findings merge regardless of source."""
    return _SAST_DAST_PREFIX.sub("", title).strip()


def _detection_method(title: str) -> str:
    m = _SAST_DAST_PREFIX.match(title)
    if m:
        return m.group(1).upper()
    return "DAST"


def deduplicate_findings(raw: list[dict]) -> list[dict]:
    """
    Merge findings by (normalized_title, affected_url):
      - Keep highest severity / risk_score / cvss_score
      - Collect all detection methods → detection_methods: ["SAST","DAST"]
      - Group same-title findings on different URLs → affected_urls list
      - Attach duplicate_count so the UI can show it
    Returns a new list, sorted by risk_score desc.
    """
    # Step 1 — merge by (norm_title, url): SAST + DAST same endpoint
    by_key: dict[tuple, dict] = {}
    for f in raw:
        norm  = _normalize_title(f["title"])
        key   = (norm, f["affected_url"])
        meth  = _detection_method(f["title"])

        if key not in by_key:
            merged = dict(f)               # copy
            merged["title"]             = norm
            merged["detection_methods"] = [meth]
            merged["duplicate_count"]   = 1
            by_key[key] = merged
        else:
            existing = by_key[key]
            existing["duplicate_count"] += 1
            if meth not in existing["detection_methods"]:
                existing["detection_methods"].append(meth)
            # Keep highest risk
            if f["risk_score"] > existing["risk_score"]:
                existing["risk_score"] = f["risk_score"]
            if f.get("cvss_score") and (
                existing.get("cvss_score") is None
                or f["cvss_score"] > existing["cvss_score"]
            ):
                existing["cvss_score"] = f["cvss_score"]
            if SEV_RANK.get(_enum_val_str(f["severity"]), 0) > SEV_RANK.get(
                _enum_val_str(existing["severity"]), 0
            ):
                existing["severity"] = f["severity"]
            # Merge confidence → average
            existing["confidence"] = (existing["confidence"] + f["confidence"]) / 2

    # Step 2 — group same title across different URLs (e.g. 8× TRACE)
    by_title: dict[str, list] = {}
    for (norm, url), merged in by_key.items():
        by_title.setdefault(norm, []).append(merged)

    result = []
    for norm_title, group in by_title.items():
        if len(group) == 1:
            result.append(group[0])
        else:
            # Pick the representative (highest risk_score)
            rep = max(group, key=lambda x: x["risk_score"])
            rep = dict(rep)
            rep["affected_urls"] = sorted({g["affected_url"] for g in group})
            rep["affected_url"]  = rep["affected_urls"][0]   # keep field for compat
            rep["duplicate_count"] = sum(g["duplicate_count"] for g in group)
            # Merge detection methods
            methods = set()
            for g in group:
                methods.update(g.get("detection_methods", []))
            rep["detection_methods"] = sorted(methods)
            result.append(rep)

    result.sort(key=lambda x: x["risk_score"], reverse=True)
    return result


def _enum_val_str(v) -> str:
    return v.value if hasattr(v, "value") else str(v)


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.get("")
async def list_findings(
    scan_id:    Optional[str] = None,
    severity:   Optional[str] = None,
    owasp:      Optional[str] = None,
    page:       int = 1,
    per_page:   int = 50,
    dedupe:     bool = True,          # ← new: ?dedupe=false to get raw
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_viewer),
):
    q = (
        select(Finding)
        .where(Finding.org_id == current_user.org_id)
        .order_by(desc(Finding.detected_at))
    )
    if scan_id:
        q = q.where(Finding.scan_id == scan_id)
    if severity:
        q = q.where(Finding.severity == severity.lower())
    if owasp:
        q = q.where(Finding.owasp_category == owasp.upper())

    # Fetch a larger window for dedup, then paginate after
    if dedupe:
        result = await db.execute(q)                         # all rows
        raw    = [_finding_dict(f) for f in result.scalars().all()]
        deduped = deduplicate_findings(raw)
        total   = len(deduped)
        start   = (page - 1) * per_page
        findings_page = deduped[start: start + per_page]
    else:
        q      = q.offset((page - 1) * per_page).limit(per_page)
        result = await db.execute(q)
        findings_page = [_finding_dict(f) for f in result.scalars().all()]
        total = len(findings_page)

    return {"findings": findings_page, "page": page, "total": total, "deduplicated": dedupe}


@router.get("/{finding_id}")
async def get_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_viewer),
):
    r = await db.execute(
        select(Finding).where(
            Finding.id == finding_id, Finding.org_id == current_user.org_id
        )
    )
    f = r.scalar_one_or_none()
    if not f:
        raise HTTPException(404, "Finding not found")
    return _finding_dict(f)


@router.patch("/{finding_id}/status")
async def update_finding_status(
    finding_id: str,
    body: dict,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_analyst),
):
    r = await db.execute(
        select(Finding).where(
            Finding.id == finding_id, Finding.org_id == current_user.org_id
        )
    )
    f = r.scalar_one_or_none()
    if not f:
        raise HTTPException(404, "Finding not found")

    allowed = ["open", "in_review", "accepted", "fixed", "false_positive"]
    new_status = body.get("status", "")
    if new_status not in allowed:
        raise HTTPException(422, f"Status must be one of: {allowed}")

    f.status = new_status
    if new_status == "false_positive":
        f.is_false_positive = True
        f.fp_reason = body.get("reason", "")

    db.add(AuditLog(
        org_id=current_user.org_id,
        user_id=current_user.id,
        action="FINDING_STATUS_UPDATED",
        resource_type="finding",
        resource_id=finding_id,
        details={"new_status": new_status},
    ))
    await db.commit()
    return {"id": finding_id, "status": new_status}

# ── ML Severity Prediction Endpoints ──────────────────────────────────────────

@router.get("/{finding_id}/ml-predict")
async def ml_predict_single(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_viewer),
):
    """
    ML-based severity prediction for a single finding.
    Returns predicted severity, confidence, and probability distribution.
    Does NOT modify the finding — read-only analysis.
    """
    r = await db.execute(
        select(Finding).where(
            Finding.id == finding_id, Finding.org_id == current_user.org_id
        )
    )
    f = r.scalar_one_or_none()
    if not f:
        raise HTTPException(404, "Finding not found")

    finding_dict = _finding_dict(f)
    ml_result    = predict_severity(finding_dict)

    return {
        "finding_id":             finding_id,
        "rule_based_severity":    finding_dict["severity"],
        "cvss_score":             finding_dict["cvss_score"],
        "risk_score":             finding_dict["risk_score"],
        **ml_result,
    }


@router.post("/ml-batch-predict")
async def ml_batch_predict(
    body: dict,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_viewer),
):
    """
    ML-based severity prediction for multiple findings by scan_id.
    Body: { "scan_id": "..." }
    Returns list of predictions for all findings in the scan.
    """
    scan_id = body.get("scan_id")
    if not scan_id:
        raise HTTPException(422, "scan_id is required")

    result = await db.execute(
        select(Finding).where(
            Finding.scan_id == scan_id,
            Finding.org_id  == current_user.org_id
        )
    )
    findings = [_finding_dict(f) for f in result.scalars().all()]
    if not findings:
        raise HTTPException(404, "No findings for this scan")

    predictions = batch_predict(findings)

    # Summary stats
    agrees = sum(1 for p in predictions if p["agrees_with_rule_based"])
    return {
        "scan_id":          scan_id,
        "total_findings":   len(findings),
        "predictions":      predictions,
        "model_agreement":  round(agrees / len(predictions), 3) if predictions else 0,
        "summary": {
            "agrees":   agrees,
            "disagrees": len(predictions) - agrees,
        }
    }
