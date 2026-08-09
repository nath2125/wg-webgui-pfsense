"""Thin async client for the pfSense REST API v2 (WireGuard endpoints).

Schemas verified live against the installed package:
  POST   /api/v2/vpn/wireguard/peer      body: {enabled, tun, descr, publickey,
                                               endpoint, port, persistentkeepalive,
                                               allowedips:[{address, mask, descr}]}
  GET    /api/v2/vpn/wireguard/peers      -> {data: [ {id, tun, descr, publickey,
                                                        allowedips:[...] }, ... ]}
  DELETE /api/v2/vpn/wireguard/peer?id=&apply=
  POST   /api/v2/vpn/wireguard/apply
  GET    /api/v2/vpn/wireguard/apply      -> {data: {applied: bool}}

Every response is the standard envelope {code, status, message, data, ...}.
The API key is sent in the X-API-Key header and is NEVER logged.
"""
from __future__ import annotations

import logging
import re

import httpx

logger = logging.getLogger("pfsense")

# A pfSense WireGuard tunnel is always "tun_wgN"-shaped. The name is settable through
# the setup wizard and is still validated on the way in: it is no longer interpolated
# into a shell command, but run_command() remains available and the constraint keeps
# any future caller from reintroducing that hazard.
_TUNNEL_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


def valid_tunnel_name(name: str) -> bool:
    return bool(_TUNNEL_RE.match(name or ""))


class PfSenseAPIError(RuntimeError):
    """Raised when pfSense returns a non-success envelope or transport fails.

    The message is safe to surface to the UI; it never contains the API key.
    """

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class PfSenseClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        tunnel: str,
        verify_tls: bool = False,
        timeout: float = 15.0,
    ):
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self.tunnel = tunnel
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers={"X-API-Key": api_key, "Accept": "application/json"},
            verify=verify_tls,
            timeout=timeout,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    # ---- low-level ----
    async def _request(self, method: str, path: str, **kwargs) -> dict:
        try:
            resp = await self._client.request(method, path, **kwargs)
        except httpx.HTTPError as e:
            # str(e) may include the URL but never headers/api key.
            logger.warning("pfSense transport error on %s %s: %s", method, path, e)
            raise PfSenseAPIError(f"Could not reach pfSense API: {e}") from e

        try:
            body = resp.json()
        except ValueError:
            body = {}

        if resp.status_code >= 400 or (body.get("code") and body["code"] >= 400):
            # Surface the API's own message, not the raw body (avoids leaking anything).
            msg = body.get("message") or f"HTTP {resp.status_code}"
            logger.warning("pfSense API error on %s %s: %s", method, path, msg)
            raise PfSenseAPIError(msg, status_code=resp.status_code)
        return body

    # ---- tunnels ----
    async def list_tunnels(self) -> list[dict]:
        body = await self._request(
            "GET", "/api/v2/vpn/wireguard/tunnels", params={"limit": 0}
        )
        data = body.get("data") or []
        return data if isinstance(data, list) else []

    async def get_tunnel_by_name(self, name: str) -> dict | None:
        for t in await self.list_tunnels():
            if t.get("name") == name:
                return t
        return None

    # ---- peers ----
    async def list_peers(self) -> list[dict]:
        # limit=0 returns all objects in this API.
        body = await self._request(
            "GET", "/api/v2/vpn/wireguard/peers", params={"limit": 0}
        )
        data = body.get("data") or []
        return data if isinstance(data, list) else []

    async def find_peer_by_pubkey(self, public_key: str) -> dict | None:
        for peer in await self.list_peers():
            if peer.get("publickey") == public_key:
                return peer
        return None

    async def find_peer_by_descr(self, descr: str) -> dict | None:
        for peer in await self.list_peers():
            if peer.get("descr") == descr:
                return peer
        return None

    async def create_peer(
        self,
        *,
        public_key: str,
        descr: str,
        allowed_ips: list[dict],
        persistent_keepalive: int | None = None,
    ) -> dict:
        """Create a WireGuard peer. Does NOT apply — caller schedules the apply.

        allowed_ips is a list of {address, mask, descr} entries (the peer's routed
        addresses on pfSense: its tunnel /32 plus any subnets behind it).
        """
        payload: dict = {
            "enabled": True,
            "tun": self.tunnel,
            "descr": descr,
            "publickey": public_key,
            "endpoint": None,  # dynamic (road-warrior) peer
            "allowedips": allowed_ips,
        }
        if persistent_keepalive is not None:
            payload["persistentkeepalive"] = persistent_keepalive
        body = await self._request("POST", "/api/v2/vpn/wireguard/peer", json=payload)
        return body.get("data") or {}

    async def patch_peer(self, peer_id: int, **fields) -> dict:
        """Partial update of a peer (e.g. enabled, publickey). Does not apply."""
        payload = {"id": peer_id, **fields}
        body = await self._request("PATCH", "/api/v2/vpn/wireguard/peer", json=payload)
        return body.get("data") or {}

    async def delete_peer(self, peer_id: int, *, apply: bool = False) -> None:
        await self._request(
            "DELETE",
            "/api/v2/vpn/wireguard/peer",
            params={"id": peer_id, "apply": str(apply).lower()},
        )

    # ---- live status ----
    async def run_command(self, command: str) -> tuple[int, str]:
        """Run a shell command on the firewall.

        pfSense executes this as root, so the API key needs
        `api-v2-diagnostics-command-prompt-post` — effectively full control of the
        appliance. Nothing on the read path uses this any more; keep it that way.
        """
        body = await self._request(
            "POST", "/api/v2/diagnostics/command_prompt", json={"command": command}
        )
        data = body.get("data") or {}
        return data.get("result_code", -1), data.get("output", "")

    async def wg_dump(self) -> dict[str, dict]:
        """Return {public_key: {latest_handshake, rx, tx, endpoint}} for this tunnel.

        Sourced from /api/v2/status/wireguard/peers (REST API pkg >= v2.9.0), which
        reports the same counters `wg show <tun> dump` does without needing the
        root-shell diagnostics endpoint.

        Note this does NOT carry the preshared key: the status model marks that field
        `sensitive`, so the API redacts it. Callers that need the PSK must get it
        elsewhere — see the reissue path in main.py.
        """
        body = await self._request(
            "GET", "/api/v2/status/wireguard/peers", params={"limit": 0}
        )
        peers: dict[str, dict] = {}
        for p in body.get("data") or []:
            if p.get("tunnel_device") != self.tunnel:
                continue
            pk = p.get("public_key")
            if not pk:
                continue
            endpoint = p.get("endpoint")
            peers[pk] = {
                "latest_handshake": p.get("latest_handshake") or 0,
                "rx": p.get("transfer_rx") or 0,
                "tx": p.get("transfer_tx") or 0,
                "endpoint": endpoint if endpoint not in ("(none)", "") else None,
            }
        return peers

    # ---- apply ----
    async def apply(self) -> dict:
        body = await self._request("POST", "/api/v2/vpn/wireguard/apply", json={})
        return body.get("data") or {}

    async def apply_status(self) -> dict:
        body = await self._request("GET", "/api/v2/vpn/wireguard/apply")
        return body.get("data") or {}
