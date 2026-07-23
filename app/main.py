"""WireGuard Web-Interface — manage pfSense WireGuard peers from one admin UI.

This app does NOT manage access control. pfSense firewall rules govern what any
peer may reach. This app assigns a free /32 from the pool, pushes the peer to
pfSense, applies, and hands back a client config + QR.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select
from starlette.middleware.sessions import SessionMiddleware

from .apply import ApplyManager
from .config import get_settings
from .db import engine, get_session, init_db
from .delivery import decrypt_config, encrypt_config, send_config_email, token_id_hash
from .ippool import PoolExhaustedError, allocate_ip, is_in_pool, iter_pool
from .models import AuditLog, ConfigLink, Device
from .pfsense import PfSenseAPIError, PfSenseClient
from .setup import RuntimeConfig, SetupStore, load_runtime_config
from .schemas import (
    ChangePassword,
    ClientConfigContext,
    DeviceCreate,
    DeviceEdit,
    DeviceImport,
    EmailConfig,
    KeepaliveAll,
    LinkCreate,
    RevokeRequest,
    RotateRequest,
    ToggleRequest,
)
from .security import (
    LoginGuard,
    client_ip,
    generate_totp_secret,
    get_or_create_csrf,
    hash_password,
    totp_provisioning_uri,
    verify_csrf,
    verify_password,
    verify_totp,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("app")

settings = get_settings()
BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

_alloc_lock = asyncio.Lock()
_login_guard = LoginGuard(settings.login_max_attempts, settings.login_lockout_seconds)


def _as_utc(dt: datetime) -> datetime:
    """Stored datetimes are UTC; SQLite may return them naive. Make them aware."""
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _iso(dt: datetime | None) -> str | None:
    return _as_utc(dt).isoformat() if dt else None


async def _expiry_sweeper(app: FastAPI, interval: int = 60) -> None:
    """Auto-revoke devices whose expiry has passed."""
    while True:
        await asyncio.sleep(interval)
        try:
            now = datetime.now(timezone.utc)
            with Session(engine) as session:
                # Filter in Python to avoid SQLite datetime string-comparison pitfalls.
                candidates = session.exec(
                    select(Device).where(
                        Device.revoked == False,  # noqa: E712
                        Device.expires_at != None,  # noqa: E711
                    )
                ).all()
                # Purge expired one-time links (ciphertext) while we're here.
                stale_links = session.exec(
                    select(ConfigLink).where(ConfigLink.expires_at <= now)
                ).all()
                for lk in stale_links:
                    session.delete(lk)
                if stale_links:
                    session.commit()

                due = [d for d in candidates if _as_utc(d.expires_at) <= now]
                if not due:
                    continue
                client = app.state.pf
                if client is None:  # setup mode: nothing to reconcile
                    continue
                removed_any = False
                for dev in due:
                    try:
                        peer = await client.find_peer_by_pubkey(dev.public_key)
                        if peer is not None and peer.get("id") is not None:
                            await client.delete_peer(int(peer["id"]), apply=False)
                            removed_any = True
                    except PfSenseAPIError as e:
                        logger.warning("expiry: could not remove %s: %s", dev.name, e)
                        continue
                    dev.revoked = True
                    dev.revoked_at = now
                    session.add(dev)
                    session.add(AuditLog(actor="system", action="expired", target=dev.name))
                    logger.info("expired and revoked %s", dev.name)
                session.commit()
                if removed_any:
                    app.state.apply.request()
        except asyncio.CancelledError:
            raise
        except Exception as e:  # never let the sweeper die
            logger.warning("expiry sweeper error: %s", e)


async def rebuild_pf(app: FastAPI) -> None:
    """(Re)build the pfSense client + apply manager from the effective config.

    Leaves ``app.state.pf = None`` when the instance isn't configured yet (setup mode),
    so the app can still boot and serve the onboarding wizard. Safe to call again after
    the wizard saves new settings — it tears down the previous client/apply first.
    """
    cfg_obj = load_runtime_config(settings)
    app.state.cfg = cfg_obj

    old_client = getattr(app.state, "pf", None)
    old_apply = getattr(app.state, "apply", None)
    if old_apply is not None:
        try:
            await old_apply.stop()
        except Exception:  # noqa: BLE001 — teardown must not raise
            pass
    if old_client is not None:
        try:
            await old_client.aclose()
        except Exception:  # noqa: BLE001
            pass

    app.state.endpoint_port = cfg_obj.wg_endpoint_port
    if not cfg_obj.configured:
        app.state.pf = None
        app.state.apply = None
        app.state.server_pubkey = ""
        logger.info("Setup mode: pfSense not configured yet — open /setup to onboard.")
        return

    client = PfSenseClient(
        cfg_obj.pfsense_api_url,
        cfg_obj.pfsense_api_key,
        tunnel=cfg_obj.wg_tunnel,
        verify_tls=cfg_obj.pfsense_verify_tls,
        timeout=settings.pfsense_timeout,
    )
    mgr = ApplyManager(client, settings.apply_debounce_seconds)
    mgr.start()

    # Auto-discover the server tunnel public key if not pinned.
    server_pubkey = cfg_obj.wg_server_public_key
    try:
        tun = await client.get_tunnel_by_name(cfg_obj.wg_tunnel)
        if tun:
            if not server_pubkey:
                server_pubkey = tun.get("publickey", "")
                logger.info("Discovered server public key from tunnel %s", cfg_obj.wg_tunnel)
        else:
            logger.warning("Tunnel %s not found on pfSense!", cfg_obj.wg_tunnel)
    except PfSenseAPIError as e:
        logger.warning("Could not read tunnel at startup: %s", e)

    app.state.pf = client
    app.state.apply = mgr
    app.state.server_pubkey = server_pubkey
    if not server_pubkey:
        logger.warning("No server public key yet; client configs will be incomplete.")
    logger.info("Configured. pfSense=%s tunnel=%s pool=%s",
                cfg_obj.pfsense_api_url, cfg_obj.wg_tunnel, cfg_obj.ip_pool_cidr)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    app.state.pf = None
    app.state.apply = None
    await rebuild_pf(app)
    sweeper = asyncio.create_task(_expiry_sweeper(app), name="expiry-sweeper")
    try:
        yield
    finally:
        sweeper.cancel()
        try:
            await sweeper
        except asyncio.CancelledError:
            pass
        if app.state.apply is not None:
            await app.state.apply.stop()
        if app.state.pf is not None:
            await app.state.pf.aclose()


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    max_age=settings.session_max_age,
    same_site="lax",
    https_only=settings.session_https_only,
)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


# --------------------------------------------------------------------------- #
# Security headers
# --------------------------------------------------------------------------- #
_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = _CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if settings.enable_hsts:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


# --------------------------------------------------------------------------- #
# Helpers / deps
# --------------------------------------------------------------------------- #
def is_authed(request: Request) -> bool:
    return bool(request.session.get("user"))


def require_api_auth(request: Request) -> None:
    if not is_authed(request):
        raise HTTPException(status_code=401, detail="Authentication required")


def require_csrf(request: Request) -> None:
    if not verify_csrf(request, request.headers.get("x-csrf-token")):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")


def _admin_hash() -> str:
    """Effective admin scrypt hash: the writable password file wins, then env."""
    if settings.admin_password_file:
        try:
            with open(settings.admin_password_file, "r", encoding="utf-8") as f:
                h = f.read().strip()
                if h:
                    return h
        except OSError:
            pass
    return settings.admin_password_hash


def _verify_admin_password(password: str) -> bool:
    h = _admin_hash()
    if h:
        return verify_password(password, h)
    return hmac.compare_digest(password, settings.admin_password)


def _load_totp() -> dict:
    if not settings.totp_file:
        return {}
    try:
        with open(settings.totp_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_totp(data: dict) -> None:
    tmp = settings.totp_file + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, settings.totp_file)


def _totp_enabled() -> bool:
    d = _load_totp()
    return bool(d.get("enabled") and d.get("secret"))


def pf(request: Request) -> PfSenseClient:
    return request.app.state.pf


def cfg(request: Request) -> RuntimeConfig:
    return request.app.state.cfg


def is_configured(app: FastAPI) -> bool:
    return getattr(app.state, "pf", None) is not None


def apply_mgr(request: Request) -> ApplyManager:
    return request.app.state.apply


def _short_key(pk: str) -> str:
    return (pk[:10] + "…" + pk[-4:]) if len(pk) > 16 else pk


def audit(session: Session, actor: str, action: str, target: str = "", detail: str = "") -> None:
    session.add(AuditLog(actor=actor, action=action, target=target, detail=detail))
    session.commit()


def _peer_keepalive(peer: dict) -> int | None:
    """PersistentKeepalive on a pfSense peer, or None when unset.

    The API returns this as an int, a numeric string, or "" depending on version,
    so normalize before comparing.
    """
    raw = peer.get("persistentkeepalive")
    if raw is None or raw == "":
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _config_context(
    request: Request,
    name: str,
    ip: str,
    allowed_ips: list[str],
    keepalive: int | None = None,
) -> ClientConfigContext:
    """Build the client .conf context. `keepalive=None` uses the configured default."""
    return ClientConfigContext(
        name=name,
        address_cidr=f"{ip}/32",
        dns=settings.wg_client_dns,
        endpoint=f"{cfg(request).wg_endpoint_host}:{request.app.state.endpoint_port}",
        server_public_key=request.app.state.server_pubkey,
        allowed_ips=allowed_ips or cfg(request).default_allowed_ips,
        persistent_keepalive=(
            settings.wg_persistent_keepalive if keepalive is None else keepalive
        ),
        mtu=settings.wg_client_mtu,
    )


def _live_for(entry: dict | None) -> dict | None:
    if not entry:
        return None
    hs = entry.get("latest_handshake") or 0
    now = int(datetime.now(timezone.utc).timestamp())
    return {
        "last_handshake": hs or None,           # unix seconds, None = never
        "seconds_ago": (now - hs) if hs else None,
        "online": bool(hs) and (now - hs) <= 180,
        "rx": entry.get("rx", 0),
        "tx": entry.get("tx", 0),
    }


def _active_devices(session: Session) -> dict[str, Device]:
    rows = session.exec(select(Device).where(Device.revoked == False)).all()  # noqa: E712
    return {d.public_key: d for d in rows}


# --------------------------------------------------------------------------- #
# Auth routes
# --------------------------------------------------------------------------- #
@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    if is_authed(request):
        return RedirectResponse("/", status_code=303)
    csrf = get_or_create_csrf(request)
    return templates.TemplateResponse(
        request, "login.html",
        {"error": None, "csrf": csrf, "app_name": settings.app_name, "show_2fa": _totp_enabled()},
    )


@app.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(""),
    totp_code: str = Form(""),
    session: Session = Depends(get_session),
):
    ip = client_ip(request)
    locked = _login_guard.seconds_locked(ip)
    if locked:
        return templates.TemplateResponse(
            request, "login.html",
            {"error": f"Too many attempts. Try again in {locked}s.",
             "csrf": get_or_create_csrf(request), "app_name": settings.app_name},
            status_code=429,
        )
    if not verify_csrf(request, csrf_token):
        raise HTTPException(403, "Invalid or missing CSRF token")

    ok_user = hmac.compare_digest(username, settings.admin_username)
    ok_pass = _verify_admin_password(password)

    if ok_user and ok_pass:
        # Second factor, if enabled.
        if _totp_enabled():
            if not verify_totp(_load_totp()["secret"], totp_code):
                _login_guard.record_failure(ip)
                msg = "Enter your 6-digit code" if not totp_code else "Invalid authentication code"
                audit(session, username, "login_2fa_failed", detail=f"from {ip}")
                return templates.TemplateResponse(
                    request, "login.html",
                    {"error": msg, "csrf": get_or_create_csrf(request),
                     "app_name": settings.app_name, "show_2fa": True},
                    status_code=401,
                )
        _login_guard.record_success(ip)
        request.session["user"] = username
        get_or_create_csrf(request)  # rotate a token into the authed session
        audit(session, username, "login", detail=f"from {ip}")
        return RedirectResponse("/", status_code=303)

    _login_guard.record_failure(ip)
    audit(session, username or "?", "login_failed", detail=f"from {ip}")
    return templates.TemplateResponse(
        request, "login.html",
        {"error": "Invalid credentials", "csrf": get_or_create_csrf(request),
         "app_name": settings.app_name, "show_2fa": _totp_enabled()},
        status_code=401,
    )


@app.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.post("/api/2fa/setup")
async def twofa_setup(
    request: Request,
    _: None = Depends(require_api_auth),
    __: None = Depends(require_csrf),
):
    if not settings.totp_file:
        raise HTTPException(400, "2FA requires TOTP_FILE to be configured.")
    secret = generate_totp_secret()
    _save_totp({"secret": secret, "enabled": False})  # pending until confirmed
    uri = totp_provisioning_uri(secret, settings.admin_username, settings.app_name)
    return {"secret": secret, "otpauth_uri": uri}


@app.post("/api/2fa/enable")
async def twofa_enable(
    request: Request,
    _: None = Depends(require_api_auth),
    __: None = Depends(require_csrf),
    session: Session = Depends(get_session),
):
    body = await request.json()
    data = _load_totp()
    if not data.get("secret"):
        raise HTTPException(400, "Start setup first.")
    if not verify_totp(data["secret"], str(body.get("code", ""))):
        raise HTTPException(403, "Incorrect code — check your authenticator's time sync.")
    data["enabled"] = True
    _save_totp(data)
    audit(session, request.session["user"], "2fa_enabled")
    return {"ok": True}


@app.post("/api/2fa/disable")
async def twofa_disable(
    request: Request,
    _: None = Depends(require_api_auth),
    __: None = Depends(require_csrf),
    session: Session = Depends(get_session),
):
    body = await request.json()
    data = _load_totp()
    if not (data.get("enabled") and data.get("secret")):
        return {"ok": True, "already": True}
    if not verify_totp(data["secret"], str(body.get("code", ""))):
        raise HTTPException(403, "Incorrect code.")
    _save_totp({"secret": "", "enabled": False})
    audit(session, request.session["user"], "2fa_disabled")
    return {"ok": True}


# --------------------------------------------------------------------------- #
# Onboarding / setup wizard
# --------------------------------------------------------------------------- #
@app.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request):
    if not is_authed(request):
        return RedirectResponse("/login", status_code=303)
    c = cfg(request)
    return templates.TemplateResponse(
        request, "setup.html",
        {
            "app_name": settings.app_name,
            "csrf": get_or_create_csrf(request),
            "configured": is_configured(request.app),
            "env_locked": c.env_configured,
            "setup_available": bool(settings.setup_file),
            "d_url": "" if c.env_configured else c.pfsense_api_url,
            "d_tunnel": c.wg_tunnel,
            "d_endpoint_host": "" if c.env_configured else c.wg_endpoint_host,
            "d_endpoint_port": c.wg_endpoint_port,
            "d_pool": c.ip_pool_cidr,
            "d_allowed": c.wg_client_allowed_ips,
        },
    )


@app.post("/api/setup/test")
async def setup_test(
    request: Request,
    _: None = Depends(require_api_auth),
    __: None = Depends(require_csrf),
):
    body = await request.json()
    url = str(body.get("url", "")).strip()
    api_key = str(body.get("api_key", "")).strip()
    verify_tls = bool(body.get("verify_tls", False))
    if not url or not api_key:
        raise HTTPException(400, "Enter the pfSense URL and API key.")
    client = PfSenseClient(url, api_key, tunnel="", verify_tls=verify_tls,
                           timeout=settings.pfsense_timeout)
    try:
        tunnels = await client.list_tunnels()
    except PfSenseAPIError as e:
        raise HTTPException(502, f"pfSense API error: {e}") from e
    finally:
        await client.aclose()
    return {
        "ok": True,
        "tunnels": [
            {"name": t.get("name"), "publickey": t.get("publickey"),
             "listenport": t.get("listenport"), "addresses": t.get("addresses")}
            for t in tunnels
        ],
    }


@app.post("/api/setup/save")
async def setup_save(
    request: Request,
    _: None = Depends(require_api_auth),
    __: None = Depends(require_csrf),
    session: Session = Depends(get_session),
):
    if not settings.setup_file:
        raise HTTPException(400, "SETUP_FILE is not configured; onboarding is disabled.")
    if cfg(request).env_configured:
        raise HTTPException(400, "This instance is configured via environment variables.")
    body = await request.json()
    url = str(body.get("url", "")).strip()
    api_key = str(body.get("api_key", "")).strip()
    tunnel = str(body.get("tunnel", "")).strip()
    endpoint_host = str(body.get("endpoint_host", "")).strip()
    if not (url and api_key and tunnel and endpoint_host):
        raise HTTPException(400, "URL, API key, tunnel and endpoint host are required.")
    try:
        endpoint_port = int(body.get("endpoint_port") or 51820)
    except (TypeError, ValueError):
        raise HTTPException(400, "Endpoint port must be a number.")
    ip_pool_cidr = str(body.get("ip_pool_cidr", "")).strip() or "192.168.90.0/24"
    client_allowed = str(body.get("client_allowed_ips", "")).strip() or "0.0.0.0/0"
    try:
        import ipaddress
        ipaddress.ip_network(ip_pool_cidr, strict=False)
    except ValueError as e:
        raise HTTPException(400, f"Invalid IP pool CIDR: {e}") from e

    SetupStore(settings.setup_file).save({
        "pfsense_api_url": url,
        "pfsense_api_key": api_key,
        "pfsense_verify_tls": bool(body.get("verify_tls", False)),
        "wg_tunnel": tunnel,
        "wg_endpoint_host": endpoint_host,
        "wg_endpoint_port": endpoint_port,
        "wg_server_public_key": str(body.get("server_public_key", "")).strip(),
        "ip_pool_cidr": ip_pool_cidr,
        "wg_client_allowed_ips": client_allowed,
    })
    await rebuild_pf(request.app)
    audit(session, request.session["user"], "setup_saved",
          detail=f"pfSense {url} tunnel {tunnel}")
    return {"ok": True, "server_pubkey": request.app.state.server_pubkey}


@app.post("/api/change_password")
async def change_password(
    request: Request,
    payload: ChangePassword,
    _: None = Depends(require_api_auth),
    __: None = Depends(require_csrf),
    session: Session = Depends(get_session),
):
    if not settings.admin_password_file:
        raise HTTPException(400, "Password changes require ADMIN_PASSWORD_FILE to be set.")
    if not _verify_admin_password(payload.current_password):
        raise HTTPException(403, "Current password is incorrect.")
    new_hash = hash_password(payload.new_password)
    try:
        # Persist the hash to the writable file (survives restarts, overrides env).
        tmp = settings.admin_password_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(new_hash + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, settings.admin_password_file)
    except OSError as e:
        raise HTTPException(500, f"Could not persist new password: {e}") from e

    # Take effect immediately for this process.
    settings.admin_password_hash = new_hash
    settings.admin_password = ""
    audit(session, request.session["user"], "change_password")
    return {"ok": True}


# --------------------------------------------------------------------------- #
# UI
# --------------------------------------------------------------------------- #
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    if not is_authed(request):
        return RedirectResponse("/login", status_code=303)
    if not is_configured(request.app):
        return RedirectResponse("/setup", status_code=303)
    c = cfg(request)
    return templates.TemplateResponse(
        request, "index.html",
        {
            "app_name": settings.app_name,
            "csrf": get_or_create_csrf(request),
            "endpoint": f"{c.wg_endpoint_host}:{request.app.state.endpoint_port}",
            "tunnel": c.wg_tunnel,
            "pool": c.ip_pool_cidr,
            "default_allowed_ips": c.wg_client_allowed_ips,
            "default_keepalive": settings.wg_persistent_keepalive,
            "presets": settings.allowedips_presets,
            "smtp_enabled": settings.smtp_enabled,
            "link_ttl_minutes": settings.link_ttl_minutes,
            "twofa_available": bool(settings.totp_file),
            "twofa_enabled": _totp_enabled(),
        },
    )


# --------------------------------------------------------------------------- #
# State (merged pfSense peers + registry)
# --------------------------------------------------------------------------- #
@app.get("/api/state")
async def api_state(
    request: Request,
    _: None = Depends(require_api_auth),
    session: Session = Depends(get_session),
):
    if not is_configured(request.app):
        return {
            "tunnel": None, "peers": [],
            "pfsense_error": "Not configured yet — open /setup.",
            "counts": {"total": 0, "managed": 0, "unmanaged": 0, "online": 0},
            "pool": {"cidr": cfg(request).ip_pool_cidr, "total": 0, "used": 0, "free": 0},
            "apply": {"last_applied_at": None, "last_error": None},
        }
    reg = _active_devices(session)
    tunnel_info = None
    pf_error = None
    peers_rows = []
    live: dict[str, dict] = {}
    try:
        client = pf(request)
        tun = await client.get_tunnel_by_name(cfg(request).wg_tunnel)
        peers = await client.list_peers()
    except PfSenseAPIError as e:
        pf_error = str(e)
        peers = []
        tun = None
    else:
        # Live handshake/transfer is best-effort; never fail state on it.
        try:
            live = await client.wg_dump()
        except PfSenseAPIError:
            live = {}

    if tun is not None:
        tunnel_info = {
            "name": tun.get("name"),
            "listenport": tun.get("listenport"),
            "publickey": tun.get("publickey"),
            "enabled": tun.get("enabled"),
        }

    seen: set[str] = set()
    for p in peers:
        if p.get("tun") and p.get("tun") != cfg(request).wg_tunnel:
            continue
        pk = p.get("publickey", "")
        seen.add(pk)
        d = reg.get(pk)
        allowed = p.get("allowedips") or []
        address = allowed[0].get("address") if allowed else None
        peers_rows.append({
            "public_key": pk,
            "public_key_short": _short_key(pk),
            "name": d.name if d else (p.get("descr") or "(unnamed peer)"),
            "assigned_ip": (d.assigned_ip if d else address) or "—",
            "allowed_ips": [
                {"address": a.get("address"), "mask": a.get("mask"), "descr": a.get("descr") or ""}
                for a in allowed
            ],
            "enabled": p.get("enabled", True),
            "persistent_keepalive": _peer_keepalive(p),
            "managed": d is not None,
            "created_here": d.created_here if d else None,
            "present": True,
            "created_at": _iso(d.created_at) if d else None,
            "expires_at": _iso(d.expires_at) if d else None,
            "client_allowed_ips": d.client_allowed_ips if d else "",
            "live": _live_for(live.get(pk)),
        })

    # Registry rows whose peer has vanished from pfSense (out of sync).
    for pk, d in reg.items():
        if pk not in seen:
            peers_rows.append({
                "public_key": pk,
                "public_key_short": _short_key(pk),
                "name": d.name,
                "assigned_ip": d.assigned_ip,
                "allowed_ips": [{"address": d.assigned_ip, "mask": 32, "descr": ""}],
                "enabled": None,
                "persistent_keepalive": None,
                "managed": True,
                "created_here": d.created_here,
                "present": False,
                "created_at": _iso(d.created_at),
                "expires_at": _iso(d.expires_at),
                "client_allowed_ips": d.client_allowed_ips,
                "live": None,
            })

    mgr = apply_mgr(request)
    # Pool utilization: count in-pool /32s currently in use across all peers.
    pool_total = sum(1 for _ in iter_pool(cfg(request)))
    used_in_pool = set()
    for r in peers_rows:
        for a in r.get("allowed_ips", []):
            if a.get("mask") == 32 and a.get("address") and is_in_pool(cfg(request), a["address"]):
                used_in_pool.add(a["address"])
    online = sum(1 for r in peers_rows if (r.get("live") or {}).get("online"))
    return {
        "tunnel": tunnel_info,
        "peers": peers_rows,
        "pfsense_error": pf_error,
        "counts": {
            "total": len(peers_rows),
            "managed": sum(1 for r in peers_rows if r["managed"]),
            "unmanaged": sum(1 for r in peers_rows if not r["managed"]),
            "online": online,
        },
        "pool": {
            "cidr": cfg(request).ip_pool_cidr,
            "total": pool_total,
            "used": len(used_in_pool),
            "free": pool_total - len(used_in_pool),
        },
        "apply": {
            "last_applied_at": mgr.last_applied_at.isoformat() if mgr.last_applied_at else None,
            "last_error": mgr.last_error,
        },
    }


@app.get("/api/audit")
async def api_audit(
    request: Request,
    _: None = Depends(require_api_auth),
    limit: int = 25,
    session: Session = Depends(get_session),
):
    rows = session.exec(
        select(AuditLog).order_by(AuditLog.ts.desc()).limit(min(limit, 100))
    ).all()
    return {"entries": [
        {"ts": _iso(r.ts), "actor": r.actor, "action": r.action,
         "target": r.target, "detail": r.detail}
        for r in rows
    ]}


# --------------------------------------------------------------------------- #
# Add / import / revoke
# --------------------------------------------------------------------------- #
@app.post("/api/devices")
async def add_device(
    request: Request,
    payload: DeviceCreate,
    _: None = Depends(require_api_auth),
    __: None = Depends(require_csrf),
    session: Session = Depends(get_session),
):
    client = pf(request)
    allowed_ips = payload.client_allowed_ips.split(", ") if payload.client_allowed_ips else cfg(request).default_allowed_ips
    keepalive = (
        settings.wg_persistent_keepalive
        if payload.persistent_keepalive is None
        else payload.persistent_keepalive
    )

    async with _alloc_lock:
        for d in _active_devices(session).values():
            if d.name.lower() == payload.name.lower():
                raise HTTPException(409, f"A device named '{d.name}' already exists.")
            if d.public_key == payload.public_key:
                raise HTTPException(409, "That public key is already registered.")

        try:
            existing_peer = await client.find_peer_by_pubkey(payload.public_key)
            all_peers = await client.list_peers()
        except PfSenseAPIError as e:
            raise HTTPException(502, f"pfSense API error: {e}") from e

        if existing_peer is not None:
            raise HTTPException(409, "A peer with this key already exists on pfSense. Use Import instead.")

        used = {d.assigned_ip for d in _active_devices(session).values()}
        for p in all_peers:
            for a in p.get("allowedips") or []:
                if a.get("address"):
                    used.add(a["address"])
        try:
            assigned_ip = allocate_ip(cfg(request), used)
        except PoolExhaustedError as e:
            raise HTTPException(409, str(e)) from e

        # First AllowedIP = the peer's own tunnel /32; then any extra routed subnets.
        peer_allowed_ips = [{"address": assigned_ip, "mask": 32, "descr": f"{payload.name} IP"}]
        for e in payload.extra_allowed_ips:
            peer_allowed_ips.append(
                {"address": e.address, "mask": e.mask, "descr": e.descr or payload.name}
            )
        try:
            await client.create_peer(
                public_key=payload.public_key,
                descr=payload.name,
                allowed_ips=peer_allowed_ips,
                persistent_keepalive=keepalive,
            )
        except PfSenseAPIError as e:
            raise HTTPException(502, f"pfSense rejected the peer: {e}") from e

        expires_at = None
        if payload.expires_days:
            expires_at = datetime.now(timezone.utc) + timedelta(days=payload.expires_days)

        device = Device(
            name=payload.name,
            public_key=payload.public_key,
            assigned_ip=assigned_ip,
            client_allowed_ips=", ".join(allowed_ips),
            created_here=True,
            expires_at=expires_at,
        )
        session.add(device)
        session.commit()
        session.refresh(device)
        detail = assigned_ip + (f" (expires in {payload.expires_days}d)" if payload.expires_days else "")
        audit(session, request.session["user"], "add", target=payload.name, detail=detail)

    apply_mgr(request).request()
    config_ctx = _config_context(request, device.name, device.assigned_ip, allowed_ips, keepalive)
    return {"device": {"id": device.id, "name": device.name, "assigned_ip": device.assigned_ip},
            "config": config_ctx.model_dump()}


@app.post("/api/devices/import")
async def import_device(
    request: Request,
    payload: DeviceImport,
    _: None = Depends(require_api_auth),
    __: None = Depends(require_csrf),
    session: Session = Depends(get_session),
):
    client = pf(request)
    async with _alloc_lock:
        if payload.public_key in _active_devices(session):
            raise HTTPException(409, "That peer is already in the registry.")
        try:
            peer = await client.find_peer_by_pubkey(payload.public_key)
        except PfSenseAPIError as e:
            raise HTTPException(502, f"pfSense API error: {e}") from e
        if peer is None:
            raise HTTPException(404, "No pfSense peer with that public key.")

        allowed = peer.get("allowedips") or []
        address = allowed[0].get("address") if allowed else None
        if not address:
            raise HTTPException(422, "That peer has no allowed IP to adopt.")
        if not is_in_pool(cfg(request), address):
            # Record it anyway, but flag: its IP is outside the managed pool.
            logger.info("Importing peer with out-of-pool IP %s", address)

        name = payload.name or peer.get("descr") or f"peer-{address}"
        device = Device(
            name=name,
            public_key=payload.public_key,
            assigned_ip=address,
            client_allowed_ips=payload.client_allowed_ips,
            created_here=False,
        )
        session.add(device)
        session.commit()
        session.refresh(device)
        audit(session, request.session["user"], "import", target=name, detail=address)
    return {"ok": True, "device": {"id": device.id, "name": device.name, "assigned_ip": device.assigned_ip}}


@app.post("/api/devices/revoke")
async def revoke_device(
    request: Request,
    payload: RevokeRequest,
    _: None = Depends(require_api_auth),
    __: None = Depends(require_csrf),
    session: Session = Depends(get_session),
):
    client = pf(request)
    try:
        peer = await client.find_peer_by_pubkey(payload.public_key)
        if peer is not None and peer.get("id") is not None:
            await client.delete_peer(int(peer["id"]), apply=False)
            scheduled = True
        else:
            scheduled = False
    except PfSenseAPIError as e:
        raise HTTPException(502, f"pfSense API error: {e}") from e

    # Mark any matching registry row revoked (frees its IP).
    dev = session.exec(
        select(Device).where(Device.public_key == payload.public_key, Device.revoked == False)  # noqa: E712
    ).first()
    target = dev.name if dev else _short_key(payload.public_key)
    if dev:
        dev.revoked = True
        dev.revoked_at = datetime.now(timezone.utc)
        session.add(dev)
        session.commit()
    audit(session, request.session["user"], "revoke", target=target)

    if scheduled:
        apply_mgr(request).request()
    return {"ok": True, "removed_from_pfsense": scheduled}


@app.post("/api/devices/edit")
async def edit_device(
    request: Request,
    payload: DeviceEdit,
    _: None = Depends(require_api_auth),
    __: None = Depends(require_csrf),
    session: Session = Depends(get_session),
):
    client = pf(request)
    dev = session.exec(
        select(Device).where(Device.public_key == payload.public_key, Device.revoked == False)  # noqa: E712
    ).first()
    if dev is None:
        raise HTTPException(404, "Device not tracked in the registry (import it first).")

    # Rename collision check.
    final_name = payload.name or dev.name
    if payload.name and payload.name.lower() != dev.name.lower():
        for other in _active_devices(session).values():
            if other.id != dev.id and other.name.lower() == payload.name.lower():
                raise HTTPException(409, f"A device named '{payload.name}' already exists.")

    try:
        peer = await client.find_peer_by_pubkey(payload.public_key)
        if peer is None or peer.get("id") is None:
            raise HTTPException(404, "No matching pfSense peer to edit.")

        patch: dict = {}
        if payload.name and payload.name != dev.name:
            patch["descr"] = payload.name

        if payload.persistent_keepalive is not None:
            patch["persistentkeepalive"] = payload.persistent_keepalive

        if payload.routed_subnets is not None:
            aips = [{"address": dev.assigned_ip, "mask": 32, "descr": f"{final_name} IP"}]
            for e in payload.routed_subnets:
                aips.append({"address": e.address, "mask": e.mask, "descr": e.descr or final_name})
            patch["allowedips"] = aips
        elif "descr" in patch:
            # Rename only: keep existing AllowedIPs, just refresh the /32's description.
            aips = [dict(a) for a in (peer.get("allowedips") or [])]
            if aips:
                aips[0]["descr"] = f"{final_name} IP"
            patch["allowedips"] = aips

        if patch:
            await client.patch_peer(int(peer["id"]), **patch)
    except PfSenseAPIError as e:
        raise HTTPException(502, f"pfSense rejected the edit: {e}") from e

    if payload.name:
        dev.name = payload.name
    if payload.change_expiry:
        dev.expires_at = (
            datetime.now(timezone.utc) + timedelta(days=payload.expires_days)
            if payload.expires_days else None
        )
    session.add(dev)
    session.commit()
    audit(session, request.session["user"], "edit", target=final_name)
    if patch:
        apply_mgr(request).request()
    return {"ok": True}


@app.post("/api/devices/keepalive_all")
async def keepalive_all(
    request: Request,
    payload: KeepaliveAll,
    _: None = Depends(require_api_auth),
    __: None = Depends(require_csrf),
    session: Session = Depends(get_session),
):
    """Set PersistentKeepalive on every peer of this tunnel in one pass.

    Backfills peers created before keepalive was configured. The whole batch
    schedules a single apply, so the tunnel bounces once rather than per peer.
    """
    client = pf(request)
    try:
        peers = await client.list_peers()
    except PfSenseAPIError as e:
        raise HTTPException(502, f"pfSense API error: {e}") from e

    tunnel = cfg(request).wg_tunnel
    updated = skipped = 0
    errors: list[str] = []
    for p in peers:
        if (p.get("tun") and p.get("tun") != tunnel) or p.get("id") is None:
            continue
        current = _peer_keepalive(p)
        # "only_missing" leaves deliberately-tuned peers alone; either way there is
        # nothing to do when the value already matches.
        if (payload.only_missing and current) or current == payload.persistent_keepalive:
            skipped += 1
            continue
        try:
            await client.patch_peer(
                int(p["id"]), persistentkeepalive=payload.persistent_keepalive
            )
            updated += 1
        except PfSenseAPIError as e:
            errors.append(f"{p.get('descr') or _short_key(p.get('publickey', ''))}: {e}")

    if updated:
        audit(session, request.session["user"], "keepalive",
              target=f"{updated} peer(s)", detail=f"{payload.persistent_keepalive}s")
        apply_mgr(request).request()
    return {"updated": updated, "skipped": skipped, "errors": errors}


@app.post("/api/devices/toggle")
async def toggle_device(
    request: Request,
    payload: ToggleRequest,
    _: None = Depends(require_api_auth),
    __: None = Depends(require_csrf),
    session: Session = Depends(get_session),
):
    client = pf(request)
    try:
        peer = await client.find_peer_by_pubkey(payload.public_key)
        if peer is None or peer.get("id") is None:
            raise HTTPException(404, "No pfSense peer with that public key.")
        await client.patch_peer(int(peer["id"]), enabled=payload.enabled)
    except PfSenseAPIError as e:
        raise HTTPException(502, f"pfSense API error: {e}") from e

    dev = session.exec(
        select(Device).where(Device.public_key == payload.public_key, Device.revoked == False)  # noqa: E712
    ).first()
    target = dev.name if dev else _short_key(payload.public_key)
    audit(session, request.session["user"], "enable" if payload.enabled else "disable", target=target)
    apply_mgr(request).request()
    return {"ok": True, "enabled": payload.enabled}


@app.post("/api/devices/import_all")
async def import_all(
    request: Request,
    _: None = Depends(require_api_auth),
    __: None = Depends(require_csrf),
    session: Session = Depends(get_session),
):
    client = pf(request)
    try:
        peers = await client.list_peers()
    except PfSenseAPIError as e:
        raise HTTPException(502, f"pfSense API error: {e}") from e

    known = _active_devices(session)
    imported = 0
    async with _alloc_lock:
        known = _active_devices(session)  # re-read under lock
        for p in peers:
            if p.get("tun") and p.get("tun") != cfg(request).wg_tunnel:
                continue
            pk = p.get("publickey", "")
            if not pk or pk in known:
                continue
            allowed = p.get("allowedips") or []
            address = allowed[0].get("address") if allowed else None
            if not address:
                continue
            name = p.get("descr") or f"peer-{address}"
            session.add(Device(name=name, public_key=pk, assigned_ip=address, created_here=False))
            imported += 1
        if imported:
            session.commit()
            audit(session, request.session["user"], "import_all", detail=f"{imported} peer(s)")
    return {"ok": True, "imported": imported}


@app.post("/api/devices/rotate")
async def rotate_device(
    request: Request,
    payload: RotateRequest,
    _: None = Depends(require_api_auth),
    __: None = Depends(require_csrf),
    session: Session = Depends(get_session),
):
    """Replace a device's keypair (new public key from the browser), keep its IP."""
    client = pf(request)
    dev = session.exec(
        select(Device).where(Device.public_key == payload.public_key, Device.revoked == False)  # noqa: E712
    ).first()
    if dev is None:
        raise HTTPException(404, "Device not found in registry (import it first).")
    if payload.new_public_key == payload.public_key:
        raise HTTPException(400, "New key is identical to the current key.")
    if payload.new_public_key in _active_devices(session):
        raise HTTPException(409, "That public key is already in use.")

    try:
        peer = await client.find_peer_by_pubkey(payload.public_key)
        if peer is None or peer.get("id") is None:
            raise HTTPException(404, "No matching pfSense peer to rotate.")
        patch: dict = {"publickey": payload.new_public_key}
        # Peers created before keepalive was set (or imported ones) have none, which
        # leaves them unable to re-establish on their own after a tunnel apply.
        # Re-issuing is the natural moment to bring them up to the configured value.
        keepalive = _peer_keepalive(peer)
        if not keepalive:
            keepalive = settings.wg_persistent_keepalive
            patch["persistentkeepalive"] = keepalive
        await client.patch_peer(int(peer["id"]), **patch)
    except PfSenseAPIError as e:
        raise HTTPException(502, f"pfSense rejected the key rotation: {e}") from e

    dev.public_key = payload.new_public_key
    session.add(dev)
    session.commit()
    session.refresh(dev)
    audit(session, request.session["user"], "rotate", target=dev.name)
    apply_mgr(request).request()

    allowed_ips = dev.client_allowed_ips.split(", ") if dev.client_allowed_ips else cfg(request).default_allowed_ips
    config_ctx = _config_context(request, dev.name, dev.assigned_ip, allowed_ips, keepalive)
    return {"ok": True, "config": config_ctx.model_dump()}


# --------------------------------------------------------------------------- #
# Config delivery: one-time link + email
# --------------------------------------------------------------------------- #
def _base_url(request: Request) -> str:
    if settings.public_base_url:
        return settings.public_base_url.rstrip("/")
    return str(request.base_url).rstrip("/")


def _conf_filename(name: str) -> str:
    safe = "".join(c if c.isalnum() or c in "._-" else "-" for c in name).strip("-")[:60]
    return (safe or "wg") + ".conf"


@app.post("/api/links")
async def create_link(
    request: Request,
    payload: LinkCreate,
    _: None = Depends(require_api_auth),
    __: None = Depends(require_csrf),
    session: Session = Depends(get_session),
):
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.link_ttl_minutes)
    link = ConfigLink(
        id_hash=token_id_hash(token),
        ciphertext=encrypt_config(token, payload.config),
        filename=_conf_filename(payload.name),
        expires_at=expires_at,
    )
    session.add(link)
    session.commit()
    audit(session, request.session["user"], "link_create", target=payload.name)
    return {
        "url": f"{_base_url(request)}/c/{token}",
        "expires_at": _iso(expires_at),
        "ttl_minutes": settings.link_ttl_minutes,
    }


def _find_valid_link(session: Session, token: str) -> ConfigLink | None:
    link = session.exec(
        select(ConfigLink).where(ConfigLink.id_hash == token_id_hash(token))
    ).first()
    if link is None or link.used:
        return None
    if _as_utc(link.expires_at) <= datetime.now(timezone.utc):
        return None
    return link


@app.get("/c/{token}", response_class=HTMLResponse)
async def link_landing(request: Request, token: str, session: Session = Depends(get_session)):
    link = _find_valid_link(session, token)
    resp = templates.TemplateResponse(
        request,
        "link_landing.html" if link else "link_invalid.html",
        {"token": token, "app_name": settings.app_name},
        status_code=200 if link else 410,
    )
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.post("/c/{token}/reveal", response_class=HTMLResponse)
async def link_reveal(request: Request, token: str, session: Session = Depends(get_session)):
    link = _find_valid_link(session, token)
    if link is None:
        resp = templates.TemplateResponse(
            request, "link_invalid.html", {"app_name": settings.app_name}, status_code=410
        )
        resp.headers["Cache-Control"] = "no-store"
        return resp
    config = decrypt_config(token, link.ciphertext)
    filename = link.filename
    # Consume: delete the row so the ciphertext is gone and the link can't be reused.
    session.delete(link)
    session.commit()
    if config is None:
        resp = templates.TemplateResponse(
            request, "link_invalid.html", {"app_name": settings.app_name}, status_code=410
        )
    else:
        resp = templates.TemplateResponse(
            request, "link_reveal.html",
            {"app_name": settings.app_name, "config": config, "filename": filename},
        )
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.post("/api/email_config")
async def email_config(
    request: Request,
    payload: EmailConfig,
    _: None = Depends(require_api_auth),
    __: None = Depends(require_csrf),
    session: Session = Depends(get_session),
):
    if not settings.smtp_enabled:
        raise HTTPException(400, "Email delivery is not configured (set SMTP_HOST/SMTP_FROM).")
    filename = _conf_filename(payload.name)
    try:
        await asyncio.to_thread(
            send_config_email, settings, payload.to, payload.name, filename, payload.config
        )
    except Exception as e:  # smtplib raises many types; don't leak internals
        logger.warning("email send failed: %s", type(e).__name__)
        raise HTTPException(502, f"Could not send email: {type(e).__name__}") from e
    audit(session, request.session["user"], "email", target=payload.name, detail=payload.to)
    return {"ok": True}


@app.get("/api/health")
async def health(request: Request, _: None = Depends(require_api_auth)):
    if not is_configured(request.app):
        return {"pfsense": "unconfigured"}
    try:
        status = await pf(request).apply_status()
        return {"pfsense": "ok", "apply": status}
    except PfSenseAPIError as e:
        return JSONResponse({"pfsense": "error", "detail": str(e)}, status_code=502)
