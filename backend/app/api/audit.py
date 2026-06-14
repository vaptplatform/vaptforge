"""Audit Log API — immutable activity trail"""
from fastapi import APIRouter, Depends
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.security import require_viewer
from app.db.session import get_db
from app.models.models import AuditLog, User

router = APIRouter()


@router.get("")
async def list_audit_logs(
    page: int = 1,
    per_page: int = 100,
    action: str = None,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_viewer),
):
    q = (
        select(AuditLog)
        .where(AuditLog.org_id == current_user.org_id)
        .order_by(desc(AuditLog.created_at))
    )
    if action:
        q = q.where(AuditLog.action == action.upper())
    q = q.offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(q)
    logs = result.scalars().all()

    # Fetch user emails for display
    user_ids = list({l.user_id for l in logs if l.user_id})
    user_map = {}
    if user_ids:
        ur = await db.execute(select(User).where(User.id.in_(user_ids)))
        user_map = {u.id: u.email for u in ur.scalars().all()}

    return {
        "logs": [
            {
                "id": l.id,
                "action": l.action,
                "user_email": user_map.get(l.user_id, "system"),
                "resource_type": l.resource_type,
                "resource_id": l.resource_id,
                "details": l.details,
                "ip_address": l.ip_address,
                "created_at": l.created_at,
            }
            for l in logs
        ],
        "page": page,
        "per_page": per_page,
    }
