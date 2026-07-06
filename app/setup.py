"""Runtime onboarding config: a writable store the in-browser setup wizard writes,
plus a RuntimeConfig overlay so the rest of the app reads one effective config.

Design:
  * If the environment already provides the pfSense connection (URL + key + endpoint),
    the instance is "env-configured" and the setup file is ignored entirely — the user's
    existing deployment behaves exactly as before.
  * Otherwise the instance is driven by the wizard: managed fields come from the setup
    file, falling back to the env defaults for anything the wizard didn't write.

The setup file holds the pfSense API key by explicit product decision (in-browser
onboarding), so it is written 0600 in the app data dir — never committed, never logged.
"""
from __future__ import annotations

import ipaddress
import json
import os

from .config import Settings

# Fields the wizard owns. Everything else (DNS, keepalive, SMTP, app_name, session,
# ip_pool_start/end/reserved, …) always comes from the environment.
MANAGED_FIELDS = (
    "pfsense_api_url",
    "pfsense_api_key",
    "pfsense_verify_tls",
    "wg_tunnel",
    "wg_endpoint_host",
    "wg_endpoint_port",
    "wg_server_public_key",
    "ip_pool_cidr",
    "wg_client_allowed_ips",
)


class SetupStore:
    """Load/save the wizard's connection settings as a 0600 JSON file."""

    def __init__(self, path: str):
        self.path = path

    @property
    def available(self) -> bool:
        return bool(self.path)

    def load(self) -> dict:
        if not self.path:
            return {}
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def save(self, data: dict) -> None:
        if not self.path:
            raise RuntimeError("SETUP_FILE is not configured; cannot persist setup.")
        # Keep only known keys; never persist stray input.
        clean = {k: data[k] for k in MANAGED_FIELDS if k in data}
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(clean, f, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)


class RuntimeConfig:
    """Effective config: env `Settings` with the wizard-managed fields overlaid.

    Delegates every non-managed attribute to the underlying env `Settings`, so it is a
    drop-in for the places that used to read `settings.<x>` (including the pool helpers
    in ippool.py, which only need pool_start/pool_end/reserved_ips/ip_pool_cidr).
    """

    def __init__(self, settings: Settings, setup_data: dict | None = None):
        object.__setattr__(self, "_s", settings)
        env_configured = bool(
            settings.pfsense_api_url
            and settings.pfsense_api_key
            and settings.wg_endpoint_host
        )
        object.__setattr__(self, "env_configured", env_configured)
        data = setup_data or {}
        vals = {}
        for k in MANAGED_FIELDS:
            env_default = getattr(settings, k)
            vals[k] = env_default if env_configured else data.get(k, env_default)
        object.__setattr__(self, "_vals", vals)

    def __getattr__(self, name):
        # Called only when normal lookup misses (class properties win over this).
        vals = object.__getattribute__(self, "_vals")
        if name in vals:
            return vals[name]
        return getattr(object.__getattribute__(self, "_s"), name)

    # ---- configured? ----
    @property
    def configured(self) -> bool:
        return bool(
            self.pfsense_api_url and self.pfsense_api_key and self.wg_endpoint_host
        )

    # ---- pool / allowed-ips recomputed from the (possibly overlaid) values ----
    @property
    def pool_network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(self.ip_pool_cidr, strict=False)

    @property
    def pool_start(self) -> ipaddress.IPv4Address:
        if self._s.ip_pool_start.strip():
            return ipaddress.ip_address(self._s.ip_pool_start.strip())
        return self.pool_network.network_address + 2

    @property
    def pool_end(self) -> ipaddress.IPv4Address:
        if self._s.ip_pool_end.strip():
            return ipaddress.ip_address(self._s.ip_pool_end.strip())
        return self.pool_network.broadcast_address - 1

    @property
    def reserved_ips(self) -> set[str]:
        reserved: set[str] = {str(self.pool_network.network_address + 1)}
        for chunk in self._s.ip_pool_reserved.split(","):
            chunk = chunk.strip()
            if chunk:
                reserved.add(str(ipaddress.ip_address(chunk)))
        return reserved

    @property
    def default_allowed_ips(self) -> list[str]:
        return [c.strip() for c in self.wg_client_allowed_ips.split(",") if c.strip()]


def load_runtime_config(settings: Settings) -> RuntimeConfig:
    return RuntimeConfig(settings, SetupStore(settings.setup_file).load())
