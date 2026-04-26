"""
AI SBC Security - TOTP Two-Factor Authentication
RFC 6238 compliant TOTP using pyotp
"""
import pyotp
import qrcode
import qrcode.image.svg
import base64
import io
from typing import Tuple


def generate_totp_secret() -> str:
    """Generate a new TOTP secret key."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str, issuer: str = "AI SBC Security") -> str:
    """Get the otpauth URI for QR code generation."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def generate_qr_code_base64(secret: str, username: str) -> str:
    """Generate QR code as base64 PNG for the frontend."""
    uri = get_totp_uri(secret, username)
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return base64.b64encode(buf.getvalue()).decode("utf-8")


def verify_totp(secret: str, token: str, valid_window: int = 1) -> bool:
    """
    Verify a TOTP token.
    valid_window: allows +/- N intervals (30s each) for clock drift.
    """
    if not secret or not token:
        return False
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(token.strip(), valid_window=valid_window)
    except Exception:
        return False


def get_current_totp(secret: str) -> str:
    """Get current TOTP value (for testing/debug only)."""
    return pyotp.TOTP(secret).now()
