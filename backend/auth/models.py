"""
AI SBC Security - Auth Pydantic Models
"""
from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional
from datetime import datetime
import re


class UserCreate(BaseModel):
    username: str
    email: str
    password: str

    @field_validator("username")
    @classmethod
    def username_valid(cls, v):
        if not re.match(r"^[a-zA-Z0-9_-]{3,32}$", v):
            raise ValueError("Username must be 3-32 chars: letters, numbers, _ or -")
        return v

    @field_validator("password")
    @classmethod
    def password_strong(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class UserLogin(BaseModel):
    username: str
    password: str
    totp_token: Optional[str] = None


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    totp_enabled: bool
    is_admin: bool
    created_at: datetime
    last_login: Optional[datetime]

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    requires_totp: bool = False
    totp_setup_required: bool = False


class TOTPSetupResponse(BaseModel):
    secret: str
    qr_code_b64: str
    uri: str


class TOTPVerifyRequest(BaseModel):
    token: str
    secret: Optional[str] = None  # Only needed during initial setup


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def password_strong(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class RefreshRequest(BaseModel):
    refresh_token: str
