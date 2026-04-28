"""
AI SBC Security - Authentication Routes
JWT + TOTP 2FA
"""
# Passlib 1.7.4 accesses bcrypt.__about__.__version__ which was removed in
# bcrypt 4.0. Patch it before passlib is imported so the CryptContext loads.
try:
    import bcrypt as _bcrypt
    if not hasattr(_bcrypt, "__about__"):
        import types as _types
        _bcrypt.__about__ = _types.SimpleNamespace(__version__=_bcrypt.__version__)
except Exception:
    pass

import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..database.db import get_db, User, AuditLog
from .models import (
    UserCreate, UserLogin, UserOut, TokenResponse,
    TOTPSetupResponse, TOTPVerifyRequest, PasswordChangeRequest, RefreshRequest
)
from .totp import generate_totp_secret, generate_qr_code_base64, get_totp_uri, verify_totp
from ..utils.time import utcnow

router = APIRouter(prefix="/api/auth", tags=["auth"])
security = HTTPBearer(auto_error=False)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

_log = logging.getLogger("ai_sbc.auth")
_env_secret = os.environ.get("SECRET_KEY")
if _env_secret:
    SECRET_KEY = _env_secret
else:
    SECRET_KEY = secrets.token_hex(32)
    _log.critical(
        "SECRET_KEY env var is NOT SET. A random key was generated for this run only — "
        "all issued JWTs and refresh tokens will be invalidated when the service restarts. "
        "Set SECRET_KEY in /etc/ai-sbc-security/env (or your environment) before going to production."
    )
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("JWT_EXPIRE_MINUTES", 60))
REFRESH_TOKEN_EXPIRE_DAYS = 7
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_token(data: dict, expires_delta: timedelta) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_tokens(user_id: int, username: str) -> dict:
    access = create_token(
        {"sub": str(user_id), "username": username, "type": "access"},
        timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    refresh = create_token(
        {"sub": str(user_id), "username": username, "type": "refresh"},
        timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )
    return {"access_token": access, "refresh_token": refresh}


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id = int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    result = await db.execute(select(User).where(User.id == user_id, User.is_active == True))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


async def get_admin_user(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


async def _audit(db: AsyncSession, action: str, user_id: Optional[int],
                 request: Request, success: bool, details: str = ""):
    log = AuditLog(
        action=action, user_id=user_id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent", ""),
        success=success, details=details
    )
    db.add(log)
    await db.commit()


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.post("/register", response_model=UserOut, status_code=201)
async def register(data: UserCreate, request: Request, db: AsyncSession = Depends(get_db)):
    """Register first user as admin, subsequent users as regular users."""
    # Check if any user exists
    result = await db.execute(select(User))
    existing = result.scalars().first()
    is_first_user = existing is None

    # Check duplicate
    dup = await db.execute(select(User).where(
        (User.username == data.username) | (User.email == data.email)
    ))
    if dup.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username or email already registered")

    user = User(
        username=data.username,
        email=data.email,
        hashed_password=hash_password(data.password),
        is_admin=is_first_user,
        is_active=True
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    await _audit(db, "register", user.id, request, True)
    return user


@router.post("/login", response_model=TokenResponse)
async def login(data: UserLogin, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == data.username))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        await _audit(db, "login_failed", None, request, False, f"Unknown user: {data.username}")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Lockout check
    if user.locked_until and user.locked_until > datetime.now(timezone.utc).replace(tzinfo=None):
        raise HTTPException(status_code=429, detail=f"Account locked. Try again later.")

    if not verify_password(data.password, user.hashed_password):
        user.failed_attempts += 1
        if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
        await db.commit()
        await _audit(db, "login_failed", user.id, request, False, "Bad password")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # TOTP check
    if user.totp_enabled:
        if not data.totp_token:
            return TokenResponse(
                access_token="", refresh_token="",
                requires_totp=True
            )
        if not verify_totp(user.totp_secret, data.totp_token):
            await _audit(db, "login_totp_failed", user.id, request, False)
            raise HTTPException(status_code=401, detail="Invalid 2FA token")

    # Success
    user.failed_attempts = 0
    user.locked_until = None
    user.last_login = utcnow()
    await db.commit()

    tokens = create_tokens(user.id, user.username)
    await _audit(db, "login_success", user.id, request, True)

    return TokenResponse(**tokens, requires_totp=False, totp_setup_required=not user.totp_enabled)


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(data: RefreshRequest, db: AsyncSession = Depends(get_db)):
    try:
        payload = jwt.decode(data.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token")
        user_id = int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    result = await db.execute(select(User).where(User.id == user_id, User.is_active == True))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    tokens = create_tokens(user.id, user.username)
    return TokenResponse(**tokens)


@router.get("/me", response_model=UserOut)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user


@router.post("/totp/setup", response_model=TOTPSetupResponse)
async def setup_totp(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Generate new TOTP secret and return QR code."""
    secret = generate_totp_secret()
    qr_b64 = generate_qr_code_base64(secret, current_user.username)
    uri = get_totp_uri(secret, current_user.username)
    # Store secret temporarily - only activated after verification
    current_user.totp_secret = secret
    await db.commit()
    return TOTPSetupResponse(secret=secret, qr_code_b64=qr_b64, uri=uri)


@router.post("/totp/verify")
async def verify_totp_setup(
    data: TOTPVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Verify TOTP token and enable 2FA."""
    secret = current_user.totp_secret
    if not secret:
        raise HTTPException(status_code=400, detail="No TOTP setup in progress")
    if not verify_totp(secret, data.token):
        raise HTTPException(status_code=400, detail="Invalid TOTP token")
    current_user.totp_enabled = True
    await db.commit()
    return {"message": "2FA enabled successfully"}


@router.delete("/totp/disable")
async def disable_totp(
    data: TOTPVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Disable 2FA (requires valid token)."""
    if not current_user.totp_enabled:
        raise HTTPException(status_code=400, detail="2FA is not enabled")
    if not verify_totp(current_user.totp_secret, data.token):
        raise HTTPException(status_code=400, detail="Invalid TOTP token")
    current_user.totp_enabled = False
    current_user.totp_secret = None
    await db.commit()
    return {"message": "2FA disabled"}


@router.post("/change-password")
async def change_password(
    data: PasswordChangeRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not verify_password(data.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    current_user.hashed_password = hash_password(data.new_password)
    await db.commit()
    await _audit(db, "password_changed", current_user.id, request, True)
    return {"message": "Password changed successfully"}
