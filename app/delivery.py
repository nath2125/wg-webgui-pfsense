"""Config delivery helpers: one-time-link encryption and SMTP email.

The one-time link stores the config encrypted with a key derived from the URL
token. The token is NEVER stored, so a database leak alone cannot decrypt the
config. Lookup uses a *separate* hash of the token so the stored lookup value
does not reveal the encryption key.
"""
from __future__ import annotations

import base64
import hashlib
import smtplib
import ssl
from email.message import EmailMessage

from cryptography.fernet import Fernet, InvalidToken

from .config import Settings


def token_id_hash(token: str) -> str:
    return hashlib.sha256(b"id:" + token.encode()).hexdigest()


def _fernet_for(token: str) -> Fernet:
    key = base64.urlsafe_b64encode(hashlib.sha256(b"enc:" + token.encode()).digest())
    return Fernet(key)


def encrypt_config(token: str, plaintext: str) -> str:
    return _fernet_for(token).encrypt(plaintext.encode()).decode()


def decrypt_config(token: str, ciphertext: str) -> str | None:
    try:
        return _fernet_for(token).decrypt(ciphertext.encode()).decode()
    except (InvalidToken, ValueError):
        return None


def send_config_email(
    settings: Settings, to_addr: str, device_name: str, filename: str, config: str
) -> None:
    """Send the config as a .conf attachment. Raises on failure. Never persists."""
    msg = EmailMessage()
    msg["From"] = settings.smtp_from
    msg["To"] = to_addr
    msg["Subject"] = f"WireGuard configuration: {device_name}"
    msg.set_content(
        f"Attached is the WireGuard configuration for '{device_name}'.\n\n"
        "It contains a private key — treat it as a secret and delete this email "
        "once you have imported the tunnel.\n"
    )
    msg.add_attachment(
        config.encode(), maintype="application", subtype="octet-stream", filename=filename
    )

    context = ssl.create_default_context()
    if settings.smtp_ssl:
        with smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, context=context, timeout=15) as s:
            if settings.smtp_user:
                s.login(settings.smtp_user, settings.smtp_password)
            s.send_message(msg)
    else:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as s:
            if settings.smtp_starttls:
                s.starttls(context=context)
            if settings.smtp_user:
                s.login(settings.smtp_user, settings.smtp_password)
            s.send_message(msg)
