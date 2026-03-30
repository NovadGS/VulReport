from __future__ import annotations

import base64
import hashlib
import io
from dataclasses import dataclass

import pyotp
import qrcode
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings

from .models import TopDevice, User


@dataclass(frozen=True)
class TotpEnrollment:
    secret: str
    provisioning_uri: str
    qr_png_base64: str


def _build_cipher() -> Fernet:
    configured_key = getattr(settings, "MFA_TOTP_ENCRYPTION_KEY", "").strip()
    if configured_key:
        key_bytes = configured_key.encode("ascii")
    else:
        # Fallback deterministic key derived from SECRET_KEY for backward compatibility.
        digest = hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest()
        key_bytes = base64.urlsafe_b64encode(digest)
    return Fernet(key_bytes)


def _encrypt_secret(raw_secret: str) -> str:
    token = _build_cipher().encrypt(raw_secret.encode("utf-8")).decode("ascii")
    return f"enc${token}"


def _decrypt_secret(stored_value: str) -> str:
    if not stored_value.startswith("enc$"):
        return stored_value
    payload = stored_value[4:]
    try:
        return _build_cipher().decrypt(payload.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return ""


def _device_secret(device: TopDevice) -> str:
    if not device.secret_key.startswith("enc$"):
        raw = device.secret_key
        device.secret_key = _encrypt_secret(raw)
        device.save(update_fields=["secret_key"])
        return raw
    return _decrypt_secret(device.secret_key)


def get_or_create_totp_device(user: User) -> TopDevice:
    device = TopDevice.objects.filter(user=user).order_by("-created_at").first()
    if device:
        return device
    return TopDevice.objects.create(
        user=user,
        secret_key=_encrypt_secret(pyotp.random_base32()),
        is_confirmed=False,
    )


def build_totp_enrollment(user: User, issuer_name: str) -> TotpEnrollment:
    device = get_or_create_totp_device(user)
    clear_secret = _device_secret(device)
    if not clear_secret:
        clear_secret = pyotp.random_base32()
        device.secret_key = _encrypt_secret(clear_secret)
        device.is_confirmed = False
        device.save(update_fields=["secret_key", "is_confirmed"])
    totp = pyotp.TOTP(clear_secret, interval=30, digits=6)
    uri = totp.provisioning_uri(name=user.email or user.username, issuer_name=issuer_name)

    img = qrcode.make(uri)
    buff = io.BytesIO()
    img.save(buff, format="PNG")
    png_b64 = base64.b64encode(buff.getvalue()).decode("ascii")
    return TotpEnrollment(secret=clear_secret, provisioning_uri=uri, qr_png_base64=png_b64)


def verify_totp_code(user: User, code: str) -> bool:
    device = TopDevice.objects.filter(user=user, is_confirmed=True).order_by("-created_at").first()
    if not device:
        return False
    clear_secret = _device_secret(device)
    if not clear_secret:
        return False
    totp = pyotp.TOTP(clear_secret, interval=30, digits=6)
    # valid_window=1 allows \(\pm 30s\) drift (usable UX, still strong enough here)
    return bool(totp.verify(code, valid_window=1))

