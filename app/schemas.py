"""Request/response models and validation helpers."""
from __future__ import annotations

import base64
import binascii
import ipaddress
import re

from pydantic import BaseModel, field_validator

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")


def valid_wg_key(value: str) -> bool:
    """A WireGuard key is 32 bytes, standard base64 (44 chars ending '=')."""
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(raw) == 32


def clean_allowed_ips(value: str) -> str:
    """Validate a comma-separated AllowedIPs list; return normalized string.

    Empty is allowed (caller substitutes the configured default).
    """
    value = (value or "").strip()
    if not value:
        return ""
    parts = [p.strip() for p in value.split(",") if p.strip()]
    for p in parts:
        try:
            ipaddress.ip_network(p, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid AllowedIPs entry '{p}': {e}") from e
    return ", ".join(parts)


def clean_keepalive(value: int | None) -> int | None:
    """Validate a PersistentKeepalive interval in seconds.

    None means "leave alone" (edit) or "use the configured default" (create);
    0 disables keepalive. WireGuard stores the interval in a 16-bit field.
    """
    if value is None:
        return None
    if not 0 <= value <= 65535:
        raise ValueError("persistent_keepalive must be 0-65535 seconds (0 = off).")
    return value


class AllowedIPEntry(BaseModel):
    """One pfSense peer AllowedIP: an address/mask routed to the peer, with a note."""
    address: str
    mask: int = 32
    descr: str = ""

    @field_validator("address")
    @classmethod
    def _check_address(cls, v: str) -> str:
        v = v.strip()
        try:
            ipaddress.ip_address(v)
        except ValueError as e:
            raise ValueError(f"Invalid address '{v}': {e}") from e
        return v

    @field_validator("mask")
    @classmethod
    def _check_mask(cls, v: int) -> int:
        if not 0 <= v <= 32:
            raise ValueError("mask must be between 0 and 32.")
        return v

    @field_validator("descr")
    @classmethod
    def _check_descr(cls, v: str) -> str:
        return (v or "").strip()[:128]


def _check_name(v: str) -> str:
    v = v.strip()
    if not _NAME_RE.match(v):
        raise ValueError(
            "Name must be 1-64 chars: letters, numbers, space, dot, dash, underscore."
        )
    return v


class DeviceCreate(BaseModel):
    name: str
    public_key: str
    client_allowed_ips: str = ""
    expires_days: int | None = None
    # Extra pfSense-side routed subnets beyond the auto-assigned /32 (e.g. a LAN
    # behind a site peer). Each has its own description.
    extra_allowed_ips: list[AllowedIPEntry] = []
    # None = use the configured WG_PERSISTENT_KEEPALIVE default.
    persistent_keepalive: int | None = None

    @field_validator("persistent_keepalive")
    @classmethod
    def _ka(cls, v: int | None) -> int | None:
        return clean_keepalive(v)

    @field_validator("extra_allowed_ips")
    @classmethod
    def _cap_extras(cls, v: list[AllowedIPEntry]) -> list[AllowedIPEntry]:
        if len(v) > 32:
            raise ValueError("Too many AllowedIP entries (max 32).")
        return v

    @field_validator("name")
    @classmethod
    def _check_name(cls, v: str) -> str:
        return _check_name(v)

    @field_validator("expires_days")
    @classmethod
    def _check_expiry(cls, v: int | None) -> int | None:
        if v is None:
            return None
        if v < 0 or v > 3650:
            raise ValueError("expires_days must be between 0 and 3650 (0 = never).")
        return v or None

    @field_validator("public_key")
    @classmethod
    def _check_key(cls, v: str) -> str:
        v = v.strip()
        if not valid_wg_key(v):
            raise ValueError("public_key must be a base64-encoded 32-byte WireGuard key.")
        return v

    @field_validator("client_allowed_ips")
    @classmethod
    def _check_aips(cls, v: str) -> str:
        return clean_allowed_ips(v)


class DeviceImport(BaseModel):
    public_key: str
    name: str | None = None
    client_allowed_ips: str = ""

    @field_validator("public_key")
    @classmethod
    def _check_key(cls, v: str) -> str:
        v = v.strip()
        if not valid_wg_key(v):
            raise ValueError("public_key must be a base64-encoded 32-byte WireGuard key.")
        return v

    @field_validator("name")
    @classmethod
    def _check_name(cls, v: str | None) -> str | None:
        return _check_name(v) if v else None

    @field_validator("client_allowed_ips")
    @classmethod
    def _check_aips(cls, v: str) -> str:
        return clean_allowed_ips(v)


class RevokeRequest(BaseModel):
    public_key: str


class DeviceEdit(BaseModel):
    public_key: str
    name: str | None = None                              # None = unchanged
    routed_subnets: list[AllowedIPEntry] | None = None   # None = unchanged; [] = clear extras
    change_expiry: bool = False                          # only touch expiry when True
    expires_days: int = 0                                # used when change_expiry; 0 = never
    persistent_keepalive: int | None = None              # None = unchanged; 0 = off

    @field_validator("persistent_keepalive")
    @classmethod
    def _ka(cls, v: int | None) -> int | None:
        return clean_keepalive(v)

    @field_validator("name")
    @classmethod
    def _check_name(cls, v: str | None) -> str | None:
        return _check_name(v) if v else None

    @field_validator("routed_subnets")
    @classmethod
    def _cap(cls, v):
        if v is not None and len(v) > 32:
            raise ValueError("Too many routed subnets (max 32).")
        return v

    @field_validator("expires_days")
    @classmethod
    def _exp(cls, v: int) -> int:
        if v < 0 or v > 3650:
            raise ValueError("expires_days must be between 0 and 3650.")
        return v


class KeepaliveAll(BaseModel):
    """Bulk-set PersistentKeepalive on the tunnel's existing pfSense peers."""
    persistent_keepalive: int
    only_missing: bool = True   # skip peers that already have a non-zero interval

    @field_validator("persistent_keepalive")
    @classmethod
    def _ka(cls, v: int) -> int:
        return clean_keepalive(v)


class ChangePassword(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def _len(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("New password must be at least 8 characters.")
        return v


class ToggleRequest(BaseModel):
    public_key: str
    enabled: bool


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_MAX_CONFIG = 8192


class LinkCreate(BaseModel):
    name: str
    config: str

    @field_validator("config")
    @classmethod
    def _check_config(cls, v: str) -> str:
        if not v.strip() or len(v) > _MAX_CONFIG:
            raise ValueError("config missing or too large.")
        return v


class EmailConfig(BaseModel):
    to: str
    name: str
    config: str

    @field_validator("to")
    @classmethod
    def _check_email(cls, v: str) -> str:
        v = v.strip()
        if not _EMAIL_RE.match(v):
            raise ValueError("Invalid email address.")
        return v

    @field_validator("config")
    @classmethod
    def _check_config(cls, v: str) -> str:
        if not v.strip() or len(v) > _MAX_CONFIG:
            raise ValueError("config missing or too large.")
        return v


class RotateRequest(BaseModel):
    public_key: str
    new_public_key: str

    @field_validator("new_public_key")
    @classmethod
    def _check_key(cls, v: str) -> str:
        v = v.strip()
        if not valid_wg_key(v):
            raise ValueError("new_public_key must be a base64-encoded 32-byte WireGuard key.")
        return v


class ClientConfigContext(BaseModel):
    """Everything the browser needs to assemble the .conf locally (no PrivateKey)."""
    name: str
    address_cidr: str
    dns: str
    endpoint: str
    server_public_key: str
    allowed_ips: list[str]
    persistent_keepalive: int
    mtu: int
