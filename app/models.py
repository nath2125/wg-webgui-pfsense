"""SQLite registry models. Store ONLY non-secret metadata.

Never stores a client private key — those are generated in the browser and
never sent to the server.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlmodel import Field, SQLModel


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Device(SQLModel, table=True):
    __tablename__ = "devices"

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    public_key: str = Field(index=True)
    assigned_ip: str = Field(index=True)
    # Client-side AllowedIPs (routing, not ACL). Blank for imported peers.
    client_allowed_ips: str = Field(default="")
    # False when the row was adopted from a pre-existing pfSense peer via import.
    created_here: bool = Field(default=True)
    created_at: datetime = Field(default_factory=_utcnow)
    expires_at: datetime | None = Field(default=None, index=True)
    revoked: bool = Field(default=False, index=True)
    revoked_at: datetime | None = Field(default=None)


class ConfigLink(SQLModel, table=True):
    """A single-use, expiring link to reveal a client config.

    The config is stored encrypted with a key derived from the URL token (which
    is NOT stored), so a database leak alone cannot decrypt it.
    """
    __tablename__ = "config_links"

    id: int | None = Field(default=None, primary_key=True)
    id_hash: str = Field(index=True)   # sha256("id:" + token)
    ciphertext: str                    # Fernet token (base64 text)
    filename: str = Field(default="wg.conf")
    created_at: datetime = Field(default_factory=_utcnow)
    expires_at: datetime = Field(index=True)
    used: bool = Field(default=False)


class AuditLog(SQLModel, table=True):
    __tablename__ = "audit_log"

    id: int | None = Field(default=None, primary_key=True)
    ts: datetime = Field(default_factory=_utcnow, index=True)
    actor: str = Field(default="")
    action: str = Field(default="")   # login, add, import, revoke, login_failed, ...
    target: str = Field(default="")   # device name / ip
    detail: str = Field(default="")
