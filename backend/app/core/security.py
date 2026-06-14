"""
Security Core - JWT, password hashing, RBAC dependencies
"""
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer()


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.API_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


class UserRoles:
    ADMIN   = "admin"
    ANALYST = "analyst"
    VIEWER  = "viewer"
    HIERARCHY = {"admin": 3, "analyst": 2, "viewer": 1}

    @classmethod
    def has_permission(cls, user_role: str, required_role: str) -> bool:
        # Normalize enum to string
        role_str = user_role.value if hasattr(user_role, "value") else str(user_role)
        return cls.HIERARCHY.get(role_str, 0) >= cls.HIERARCHY.get(required_role, 999)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
):
    """Decode JWT and return the User ORM object."""
    from app.db.session import AsyncSessionLocal
    from app.models.models import User
    from sqlalchemy import select

    payload = decode_token(credentials.credentials)
    user_id: str = payload.get("sub")

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(User).where(User.id == user_id, User.is_active == True)
        )
        user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )
    return user


def require_role(minimum_role: str):
    async def role_checker(current_user=Depends(get_current_user)):
        if not UserRoles.has_permission(current_user.role, minimum_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {minimum_role}",
            )
        return current_user
    return role_checker


require_admin   = require_role(UserRoles.ADMIN)
require_analyst = require_role(UserRoles.ANALYST)
require_viewer  = require_role(UserRoles.VIEWER)
