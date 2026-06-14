"""Users API — Team member management"""
import re
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.security import require_admin, require_viewer, hash_password
from app.db.session import get_db
from app.models.models import AuditLog, User, UserRole

router = APIRouter()

EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")


class CreateUserRequest(BaseModel):
    email: str
    full_name: str
    password: str
    role: str = "viewer"


class UpdateUserRequest(BaseModel):
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


def _role_str(role) -> str:
    return role.value if hasattr(role, "value") else str(role)


def _user_dict(u: User) -> dict:
    return {
        "id": u.id,
        "email": u.email,
        "full_name": u.full_name,
        "role": _role_str(u.role),
        "is_active": u.is_active,
        "last_login": u.last_login,
    }


@router.get("")
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_admin),
):
    r = await db.execute(
        select(User).where(User.org_id == current_user.org_id)
    )
    return {"users": [_user_dict(u) for u in r.scalars().all()]}


@router.post("", status_code=201)
async def create_user(
    data: CreateUserRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_admin),
):
    email = data.email.strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(422, "Invalid email address")

    existing = await db.execute(select(User).where(User.email == email))
    if existing.scalar_one_or_none():
        raise HTTPException(409, "Email already exists")

    # Map role string to enum
    role_map = {"admin": UserRole.ADMIN, "analyst": UserRole.ANALYST, "viewer": UserRole.VIEWER}
    role_enum = role_map.get(data.role.lower(), UserRole.VIEWER)

    user = User(
        org_id=current_user.org_id,
        email=email,
        full_name=data.full_name,
        password_hash=hash_password(data.password),
        role=role_enum,
    )
    db.add(user)
    db.add(AuditLog(
        org_id=current_user.org_id,
        user_id=current_user.id,
        action="USER_CREATED",
        details={"email": email, "role": data.role},
    ))
    await db.commit()
    return _user_dict(user)


@router.patch("/{user_id}")
async def update_user(
    user_id: str,
    data: UpdateUserRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_admin),
):
    r = await db.execute(
        select(User).where(User.id == user_id, User.org_id == current_user.org_id)
    )
    user = r.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")

    if data.full_name is not None:
        user.full_name = data.full_name
    if data.role is not None:
        role_map = {"admin": UserRole.ADMIN, "analyst": UserRole.ANALYST, "viewer": UserRole.VIEWER}
        user.role = role_map.get(data.role.lower(), user.role)
    if data.is_active is not None:
        user.is_active = data.is_active

    await db.commit()
    return _user_dict(user)
