"""
Authentication API — Login, Register, Me, Forgot Password, Reset Password
FIXED: router was accidentally overwritten by logger assignment
"""
import hashlib
import logging
import re
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, pwd_context, require_viewer
from app.db.session import get_db
from app.models.models import AuditLog, Organization, PasswordResetToken, User

router = APIRouter()
logger = logging.getLogger("vapt.api.auth")

EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
PW_MIN   = 8

RESET_TOKEN_EXPIRY_MINUTES = 30
MAX_RESET_REQUESTS_PER_HOUR = 5

_reset_attempts: dict = {}

def _check_rate_limit(email: str) -> None:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=1)
    attempts = [t for t in _reset_attempts.get(email, []) if t > cutoff]
    _reset_attempts[email] = attempts
    if len(attempts) >= MAX_RESET_REQUESTS_PER_HOUR:
        raise HTTPException(429, "Too many password reset requests. Try again in 1 hour.")
    _reset_attempts[email] = attempts + [now]


class LoginReq(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not EMAIL_RE.match(v):
            raise ValueError("Invalid email format")
        return v


class RegisterReq(BaseModel):
    email: str
    password: str
    full_name: str
    org_name: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not EMAIL_RE.match(v):
            raise ValueError("Invalid email format")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < PW_MIN:
            raise ValueError(f"Password must be at least {PW_MIN} characters")
        return v


class ForgotPasswordReq(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not EMAIL_RE.match(v):
            raise ValueError("Invalid email format")
        return v


class ResetPasswordReq(BaseModel):
    token: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < PW_MIN:
            raise ValueError(f"Password must be at least {PW_MIN} characters")
        return v


def _user_dict(user: User) -> dict:
    role_val = user.role.value if hasattr(user.role, "value") else str(user.role)
    return {
        "id":        user.id,
        "email":     user.email,
        "full_name": user.full_name,
        "role":      role_val,
        "org_id":    user.org_id,
        "last_login": str(user.last_login) if user.last_login else None,
    }


@router.post("/login")
async def login(req: LoginReq, request: Request, db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(User).where(User.email == req.email, User.is_active == True))
    user = r.scalar_one_or_none()
    if not user or not pwd_context.verify(req.password, user.password_hash):
        raise HTTPException(401, "Invalid email or password")

    token = create_access_token({"sub": user.id, "org_id": user.org_id,
                                   "role": user.role.value if hasattr(user.role, "value") else str(user.role)})
    user.last_login = datetime.now(timezone.utc)
    db.add(AuditLog(org_id=user.org_id, user_id=user.id, action="USER_LOGIN",
                     resource_type="user", resource_id=user.id,
                     details={"ip": request.client.host if request.client else "unknown"}))
    await db.commit()
    return {"access_token": token, "token_type": "bearer", "user": _user_dict(user)}


@router.post("/register")
async def register(req: RegisterReq, db: AsyncSession = Depends(get_db)):
    r = await db.execute(select(User).where(User.email == req.email))
    if r.scalar_one_or_none():
        raise HTTPException(409, "Email already registered")

    org = Organization(name=req.org_name, slug=req.org_name.lower().replace(" ", "-"))
    db.add(org)
    await db.flush()

    from app.models.models import UserRole
    user = User(
        email=req.email,
        full_name=req.full_name,
        password_hash=pwd_context.hash(req.password),
        role=UserRole.ADMIN,
        org_id=org.id,
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    token = create_access_token({"sub": user.id, "org_id": user.org_id,
                                   "role": user.role.value if hasattr(user.role, "value") else str(user.role)})
    return {"access_token": token, "token_type": "bearer", "user": _user_dict(user)}


@router.get("/me")
async def me(db: AsyncSession = Depends(get_db), current_user=Depends(require_viewer)):
    return _user_dict(current_user)


@router.post("/forgot-password")
async def forgot_password(req: ForgotPasswordReq, db: AsyncSession = Depends(get_db)):
    _check_rate_limit(req.email)

    r = await db.execute(select(User).where(User.email == req.email, User.is_active == True))
    user = r.scalar_one_or_none()

    if user:
        raw_token  = secrets.token_urlsafe(48)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=RESET_TOKEN_EXPIRY_MINUTES)

        old_tokens = await db.execute(
            select(PasswordResetToken).where(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.used == False,
            )
        )
        for old in old_tokens.scalars().all():
            old.used = True

        db.add(PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=expires_at,
            used=False,
        ))
        await db.commit()

        from app.core.config import settings
        reset_url = f"{settings.FRONTEND_URL}/reset-password?token={raw_token}"

        try:
            from app.services.email_service import email_service
            result = await email_service.send_password_reset(
                recipient=user.email,
                reset_url=reset_url,
                expiry_minutes=RESET_TOKEN_EXPIRY_MINUTES,
            )
            logger.info(f"Password reset email result → {result}")
            if not result.get("success"):
                dev_mode = result.get("dev_mode", False)
                if dev_mode:
                    # In dev mode (no SMTP), log the reset URL so developer can test
                    logger.warning(
                        f"\n{'='*60}\n"
                        f"[DEV MODE — FORGOT PASSWORD]\n"
                        f"User: {user.email}\n"
                        f"Reset URL: {reset_url}\n"
                        f"Expires in: {RESET_TOKEN_EXPIRY_MINUTES} minutes\n"
                        f"Configure SMTP_HOST + SMTP_USER + SMTP_PASS in .env to send real emails.\n"
                        f"{'='*60}"
                    )
                    # Return success response in dev mode so UI doesn't show error
                else:
                    logger.error(f"SMTP send failed for password reset to {user.email}: {result.get('message')}")
                    raise HTTPException(
                        status_code=500,
                        detail=f"Email sending failed: {result.get('message')}"
                    )
            else:
                logger.info(f"Password reset email sent successfully to {user.email}")
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to send reset email to {user.email}: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail="Failed to send password reset email")

    return {
        "message": "If that email is registered, a reset link has been sent.",
        "expiry_minutes": RESET_TOKEN_EXPIRY_MINUTES,
    }


@router.post("/reset-password")
async def reset_password(req: ResetPasswordReq, db: AsyncSession = Depends(get_db)):
    token_hash = hashlib.sha256(req.token.encode()).hexdigest()
    now = datetime.now(timezone.utc)

    r = await db.execute(
        select(PasswordResetToken).where(
            PasswordResetToken.token_hash == token_hash,
            PasswordResetToken.used == False,
            PasswordResetToken.expires_at > now,
        )
    )
    reset_token = r.scalar_one_or_none()
    if not reset_token:
        raise HTTPException(400, "Invalid or expired reset token")

    user_r = await db.execute(select(User).where(User.id == reset_token.user_id))
    user = user_r.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(400, "User not found or inactive")

    user.password_hash = pwd_context.hash(req.new_password)
    reset_token.used = True
    db.add(AuditLog(
        org_id=user.org_id, user_id=user.id,
        action="PASSWORD_RESET", resource_type="user", resource_id=user.id,
        details={"method": "token"},
    ))
    await db.commit()
    return {"message": "Password reset successfully. You can now log in."}
