"""Whitelisted Domains API"""
import secrets
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.security import require_admin, require_viewer
from app.db.session import get_db
from app.models.models import AuditLog, DomainStatus, WhitelistedDomain

router = APIRouter()

class AddDomainRequest(BaseModel):
    domain: str
    notes: str = ""

@router.get("")
async def list_domains(db: AsyncSession = Depends(get_db), current_user=Depends(require_viewer)):
    r = await db.execute(select(WhitelistedDomain).where(WhitelistedDomain.org_id == current_user.org_id))
    domains = r.scalars().all()
    return {"domains": [{"id": d.id, "domain": d.domain, "status": d.status.value if hasattr(d.status, "value") else str(d.status), "verified_at": d.verified_at, "notes": d.notes} for d in domains]}

@router.post("", status_code=201)
async def add_domain(data: AddDomainRequest, db: AsyncSession = Depends(get_db), current_user=Depends(require_admin)):
    token = secrets.token_urlsafe(24)
    domain = WhitelistedDomain(
        org_id=current_user.org_id,
        domain=data.domain.lower().strip(),
        status=DomainStatus.PENDING,
        verification_token=token,
        notes=data.notes,
        added_by=current_user.id,
    )
    db.add(domain)
    db.add(AuditLog(org_id=current_user.org_id, user_id=current_user.id, action="DOMAIN_ADDED", details={"domain": data.domain}))
    await db.commit()
    return {"id": domain.id, "domain": domain.domain, "status": domain.status.value if hasattr(domain.status, "value") else str(domain.status), "verification_token": token,
            "verification_instructions": f"Add TXT record: vapt-verify={token} to DNS of {data.domain}"}

@router.post("/{domain_id}/verify")
async def verify_domain(domain_id: str, db: AsyncSession = Depends(get_db), current_user=Depends(require_admin)):
    """In production, this would check DNS TXT record. Here we allow manual admin verification."""
    from datetime import datetime, timezone
    r = await db.execute(select(WhitelistedDomain).where(WhitelistedDomain.id == domain_id, WhitelistedDomain.org_id == current_user.org_id))
    domain = r.scalar_one_or_none()
    if not domain:
        raise HTTPException(404, "Domain not found")
    domain.status = DomainStatus.VERIFIED
    domain.verified_at = datetime.now(timezone.utc)
    db.add(AuditLog(org_id=current_user.org_id, user_id=current_user.id, action="DOMAIN_VERIFIED", details={"domain": domain.domain}))
    await db.commit()
    return {"domain": domain.domain, "status": domain.status}

@router.delete("/{domain_id}")
async def remove_domain(domain_id: str, db: AsyncSession = Depends(get_db), current_user=Depends(require_admin)):
    r = await db.execute(select(WhitelistedDomain).where(WhitelistedDomain.id == domain_id, WhitelistedDomain.org_id == current_user.org_id))
    domain = r.scalar_one_or_none()
    if not domain:
        raise HTTPException(404, "Domain not found")
    await db.delete(domain)
    db.add(AuditLog(org_id=current_user.org_id, user_id=current_user.id, action="DOMAIN_REMOVED", details={"domain": domain.domain}))
    await db.commit()
    return {"message": "Domain removed"}
