"""Configuration — everything comes from environment variables.

No secrets are ever hardcoded. See .env.example for the full list.
"""
from __future__ import annotations

import ipaddress
import json
from functools import lru_cache

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    app_name: str = "WireGuard Web-Interface"

    # --- pfSense REST API (v2, jaredhendrickson13/pfSense-pkg-RESTAPI) ---
    # These may be blank at boot: an unconfigured instance starts in "setup mode"
    # and the in-browser wizard writes them to SETUP_FILE. Env still wins when set.
    pfsense_api_url: str = Field("", description="Base URL, e.g. https://192.168.1.1")
    pfsense_api_key: str = Field("", description="X-API-Key value")
    pfsense_verify_tls: bool = Field(False, description="Verify pfSense TLS cert")
    pfsense_timeout: float = 15.0

    # --- WireGuard tunnel / endpoint ---
    wg_tunnel: str = Field("tun_wg0", description="pfSense WireGuard tunnel name")
    wg_endpoint_host: str = Field("", description="Public host clients dial, e.g. DDNS")
    wg_endpoint_port: int = 51820
    # Blank -> auto-discovered from the tunnel via the API at startup.
    wg_server_public_key: str = Field("", description="Server tunnel public key")
    wg_client_dns: str = Field("", description="DNS pushed to client (blank = omit)")
    wg_persistent_keepalive: int = 25
    wg_client_mtu: int = 0

    # Client-side AllowedIPs = routing only (what the client sends INTO the tunnel).
    # This is NOT access control — pfSense firewall rules govern what a peer may reach.
    wg_client_allowed_ips: str = Field("0.0.0.0/0", description="Default client routes")
    # Optional suggestions shown in the add form (JSON list of strings).
    wg_allowedips_presets: str = Field("", description="JSON list of AllowedIPs presets")

    # --- IP pool for peer /32 allocation ---
    ip_pool_cidr: str = Field("192.168.90.0/24", description="Peer address pool")
    ip_pool_start: str = Field("", description="First usable host (blank = .2)")
    ip_pool_end: str = Field("", description="Last usable host (blank = broadcast-1)")
    ip_pool_reserved: str = Field("", description="Extra IPs never to hand out")

    # --- Auth ---
    admin_username: str = Field("admin")
    admin_password: str = Field("", description="Admin password (plain; dev/simple)")
    admin_password_hash: str = Field("", description="scrypt hash (preferred; see hashpw)")
    # Writable file that stores the scrypt hash; enables in-UI password changes and
    # overrides ADMIN_PASSWORD/ADMIN_PASSWORD_HASH when present. Point at a writable dir.
    admin_password_file: str = Field("", description="Path to a writable password-hash file")
    # Writable JSON file storing TOTP 2FA state (secret + enabled). Blank disables 2FA.
    totp_file: str = Field("", description="Path to a writable 2FA state file")
    # Writable JSON file the setup wizard writes the pfSense connection to. Blank = the
    # wizard can't persist, so the app is env-only (no in-browser onboarding).
    setup_file: str = Field("", description="Path to a writable setup/onboarding file")
    session_secret: str = Field(..., description="Random secret for signed session cookie")
    session_max_age: int = 60 * 60 * 8
    session_https_only: bool = Field(False, description="Set Secure flag on cookie (HTTPS)")
    enable_hsts: bool = Field(False, description="Send HSTS header (only if HTTPS)")
    login_max_attempts: int = 5
    login_lockout_seconds: int = 300

    # --- Config delivery ---
    # Public base URL for building one-time links (blank = derive from request).
    public_base_url: str = Field("", description="e.g. https://vpn.example.com")
    link_ttl_minutes: int = 30
    # SMTP (email delivery). Blank host disables the email option.
    smtp_host: str = Field("", description="SMTP server host (blank disables email)")
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = Field("", description="From address, e.g. wg@example.com")
    smtp_starttls: bool = True
    smtp_ssl: bool = False  # implicit TLS (usually port 465)

    # --- Apply debounce ---
    apply_debounce_seconds: float = 2.0

    # --- Storage ---
    database_url: str = "sqlite:////data/devices.db"

    @field_validator("pfsense_api_url")
    @classmethod
    def _strip_slash(cls, v: str) -> str:
        return v.rstrip("/")

    @model_validator(mode="after")
    def _require_a_password(self) -> "Settings":
        if not (self.admin_password or self.admin_password_hash or self.admin_password_file):
            raise ValueError(
                "Set ADMIN_PASSWORD, ADMIN_PASSWORD_HASH, or ADMIN_PASSWORD_FILE."
            )
        return self

    # ---- derived helpers ----
    @property
    def smtp_enabled(self) -> bool:
        return bool(self.smtp_host and self.smtp_from)

    @property
    def default_allowed_ips(self) -> list[str]:
        return [c.strip() for c in self.wg_client_allowed_ips.split(",") if c.strip()]

    @property
    def allowedips_presets(self) -> list[str]:
        if not self.wg_allowedips_presets.strip():
            return []
        try:
            data = json.loads(self.wg_allowedips_presets)
        except json.JSONDecodeError as e:
            raise ValueError(f"WG_ALLOWEDIPS_PRESETS is not valid JSON: {e}") from e
        if not isinstance(data, list):
            raise ValueError("WG_ALLOWEDIPS_PRESETS must be a JSON list of strings")
        return [str(x) for x in data]

    @property
    def pool_network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(self.ip_pool_cidr, strict=False)

    @property
    def pool_start(self) -> ipaddress.IPv4Address:
        if self.ip_pool_start.strip():
            return ipaddress.ip_address(self.ip_pool_start.strip())
        return self.pool_network.network_address + 2

    @property
    def pool_end(self) -> ipaddress.IPv4Address:
        if self.ip_pool_end.strip():
            return ipaddress.ip_address(self.ip_pool_end.strip())
        return self.pool_network.broadcast_address - 1

    @property
    def reserved_ips(self) -> set[str]:
        reserved: set[str] = {str(self.pool_network.network_address + 1)}
        for chunk in self.ip_pool_reserved.split(","):
            chunk = chunk.strip()
            if chunk:
                reserved.add(str(ipaddress.ip_address(chunk)))
        return reserved


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
