# WireGuard Web-Interface

A self-hosted admin UI for managing WireGuard peers on an **existing pfSense box**.

**pfSense stays the WireGuard endpoint** and does all routing and **firewalling**. This
app never creates a WireGuard interface and **never manages access control** — you set
firewall/ACL rules in pfSense. What it does is make peer management one-click: it drives
the pfSense **WireGuard package** through the **pfSense REST API**
([jaredhendrickson13/pfSense-pkg-RESTAPI](https://github.com/jaredhendrickson13/pfsense-api), v2).

## What it does

- **Add device** — generates the WireGuard keypair **in your browser** (the private key
  never touches the server), assigns the **next free `/32`** from the pool (checked
  against the live pfSense peer list so it never collides), pushes the peer, applies, and
  returns a downloadable `.conf` + QR.
- **Deliver the config your way** — download `.conf`, scan a QR, copy, print, native
  share, email (when SMTP is configured), or hand out a single-use, encrypted **one-time
  link**.
- **See everything, live** — a tunnel **dashboard** (pool usage, peer counts, online now)
  plus a merged peer list showing **every** peer on the tunnel, marked *created here* /
  *imported* / *unmanaged*, each with **live handshake / online state and transfer**
  read from `wg show` on pfSense.
- **Edit in place** — rename a peer and adjust its pfSense routed subnets (AllowedIPs) and
  expiry without recreating it.
- **Import & export** — adopt pre-existing pfSense peers into the registry to name/track
  them (non-destructive), or export the inventory as CSV / JSON.
- **Expiry** — optionally auto-revoke a peer after N days.
- **Revoke** — delete a peer from pfSense, apply, and free its IP back to the pool.

The server stores **only** name, public key, assigned IP, chosen client AllowedIPs, and
timestamps. It never stores a private key.

> **AllowedIPs is routing, not ACL.** The "Client AllowedIPs" field only sets what the
> *client* routes into the tunnel (e.g. `0.0.0.0/0` full-tunnel vs specific subnets for
> split-tunnel). It has nothing to do with what a peer is *allowed to reach* — that is
> enforced entirely by your pfSense firewall rules.

---

## ⚠ Verify against your API's OpenAPI spec first

The REST API package is community-maintained and its schema shifts between versions.
Confirm the endpoints against **your** instance before trusting the integration:

```bash
curl -sk -H "X-API-Key: $PFSENSE_API_KEY" \
  https://<your-pfsense>/api/v2/schema/openapi > openapi.json
```

Verified live against a real box, these are the shapes this app uses (all in
`app/pfsense.py` — the only place the API schema is encoded):

- `POST /api/v2/vpn/wireguard/peer` — `allowedips` items are **objects**
  `{address, mask(int), descr}`, not `"x.x.x.x/32"` strings.
- `GET  /api/v2/vpn/wireguard/peers?limit=0`  ·  `GET /api/v2/vpn/wireguard/tunnels?limit=0`
- `DELETE /api/v2/vpn/wireguard/peer?id=<int>&apply=`
- `POST /api/v2/vpn/wireguard/apply`  ·  envelope `{code, status, message, data, _links}`
- `POST /api/v2/diagnostics/command_prompt` — runs `wg show <tunnel> dump` for live
  handshake/transfer status. **Optional**: if the API key lacks this privilege the app still
  works; peers just show no live status.

---

## Quick start (Docker)

You only need a **password + a session secret + a writable `SETUP_FILE`** to start — then
you connect to pfSense from the browser. No pfSense details in `.env` required:

```bash
cp .env.example .env
# minimum for the browser wizard:
#   SESSION_SECRET  (python -c "import secrets;print(secrets.token_urlsafe(48))")
#   ADMIN_PASSWORD  (or ADMIN_PASSWORD_HASH — see below)
#   SETUP_FILE=/data/setup.json   (writable; the wizard persists here)
docker compose up -d --build
```

Binds to `127.0.0.1:8000`. **Front it with your own HTTPS reverse proxy + IP allowlist** —
it holds an API credential into your firewall and assumes no public exposure. When behind
HTTPS, set `SESSION_HTTPS_ONLY=true` and `ENABLE_HSTS=true`.

### First-run setup wizard

Log in, then the app sends you to **`/setup`**:

1. Enter your **pfSense URL + REST API key** → *Test connection* (discovers your tunnels).
2. Pick the **WireGuard tunnel**, set your public **endpoint host** and the **IP pool** the
   app hands `/32`s from → *Save & connect* (server public key is auto-discovered).
3. **Import existing peers** — adopt the peers already on that tunnel in one click.

The connection is written to `SETUP_FILE` (`0600`) and the client is built at runtime — no
restart. Prefer config-as-code? Set `PFSENSE_API_URL` / `PFSENSE_API_KEY` /
`WG_ENDPOINT_HOST` in the environment instead and the wizard is skipped (env always wins).

### Run without Docker (dev)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
set -a; . ./.env; set +a
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

---

## Admin password

Preferred — store a hash, never plaintext:

```bash
python -m app.hashpw            # prompts, no echo
# paste the scrypt$... output into ADMIN_PASSWORD_HASH in .env
```

`ADMIN_PASSWORD_HASH` (scrypt, stdlib) takes precedence over `ADMIN_PASSWORD`. If only
`ADMIN_PASSWORD` is set it's compared in constant time — fine behind your proxy, but the
hash is better.

---

## Security

- **Private keys are generated in-browser** (Curve25519 via a vendored, offline copy of
  TweetNaCl) and never sent to the server; the `.conf` and QR are assembled client-side.
  If JS is unavailable the add flow fails rather than falling back to server-side keys.
- **Strict CSP + security headers** on every response (`default-src 'self'`, no inline
  script/style, `frame-ancestors 'none'`, `nosniff`, `Referrer-Policy: no-referrer`,
  optional HSTS). Vendored libs and the QR (a `data:` image) keep the page CSP-clean.
- **CSRF protection** — session-bound token required on login and every state-changing API
  call.
- **Login lockout** — after `LOGIN_MAX_ATTEMPTS` failures an IP is locked for
  `LOGIN_LOCKOUT_SECONDS`. The key is the socket address unless `TRUST_PROXY_HEADERS` says a
  trusted proxy is in front, so a spoofed `X-Forwarded-For` can't sidestep it.
- **Optional TOTP 2FA** — a time-based one-time code (RFC 6238, stdlib) on top of the
  password, set up from the UI; state lives in a writable `TOTP_FILE` (blank ⇒ hidden).
- **One-time links are encrypted at rest** and single-use; the decryption key is derived
  from the link token and never stored, so the DB alone can't reveal a config.
- **Audit log** — login/add/import/revoke (and failed logins) recorded and shown in the
  Activity panel.
- The API key is read from env or the `0600` `SETUP_FILE` (never both — env wins), never
  logged, never returned; errors surface only the pfSense-provided message. The setup wizard
  sits behind the single admin gate, so only the logged-in admin can configure the connection.
- **Transactional & collision-safe** — the registry row commits only after pfSense confirms
  the peer; IP allocation is serialized and computed from both the registry and the live
  pfSense peer list.
- **AllowedIPs can't hijack the pool** — WireGuard routes by longest-prefix match across all
  peers, so a peer AllowedIP covering the tunnel pool (or `0.0.0.0/0`) would silently steal
  the return path for every other peer and black-hole them. Entries that overlap the pool are
  rejected on both add and edit; subnets genuinely behind a peer never overlap it.
- **No shell metacharacters reach pfSense** — the tunnel name is interpolated into a `wg show`
  command that the pfSense diagnostics endpoint runs as root, so it is restricted to
  `[A-Za-z0-9_.-]` at the wizard boundary *and* re-validated immediately before use.
- **API docs are off by default** — `/docs`, `/redoc` and `/openapi.json` can't be auth-gated
  the way routes are, so they stay unmounted unless `ENABLE_API_DOCS` is set.
- **The registry is `0600`** — SQLite would otherwise create it with the process umask.

---

## Configuration

Every setting is an environment variable — see [`.env.example`](.env.example). Anything the
browser wizard manages (pfSense connection, tunnel, endpoint, pool) may be left blank and set
at `/setup` instead. Highlights:

| Variable | Purpose |
|---|---|
| `SETUP_FILE` | Writable path ⇒ enables the in-browser setup wizard (blank = env-only) |
| `PFSENSE_API_URL` / `PFSENSE_API_KEY` | Reach the REST API (or set via the wizard) |
| `WG_TUNNEL` | Tunnel name (e.g. `tun_wg0`) |
| `WG_ENDPOINT_HOST` / `WG_ENDPOINT_PORT` | What clients dial |
| `WG_SERVER_PUBLIC_KEY` | Blank ⇒ auto-discovered from the tunnel at startup |
| `WG_CLIENT_DNS` | DNS pushed to clients (blank = omit) |
| `WG_CLIENT_ALLOWED_IPS` | Default client routes (routing, not ACL) |
| `WG_ALLOWEDIPS_PRESETS` | Optional JSON list of AllowedIPs suggestions |
| `IP_POOL_CIDR` | Pool the app hands `/32`s from |
| `ADMIN_PASSWORD_HASH` / `ADMIN_PASSWORD` | The single admin gate |
| `ADMIN_PASSWORD_FILE` | Writable hash file ⇒ enables the in-UI "Change password" button |
| `TOTP_FILE` | Writable file ⇒ enables optional TOTP 2FA (blank = hidden) |
| `PUBLIC_BASE_URL` / `LINK_TTL_MINUTES` | One-time config links |
| `SMTP_HOST` / `SMTP_*` | Optional email delivery of configs |
| `SESSION_SECRET` | Signs the session cookie |
| `SESSION_HTTPS_ONLY` / `ENABLE_HSTS` | Turn on when served over HTTPS |
| `LOGIN_MAX_ATTEMPTS` / `LOGIN_LOCKOUT_SECONDS` | Brute-force lockout |
| `TRUST_PROXY_HEADERS` | Honour `X-Forwarded-For` for lockout — **only** behind a proxy you control |
| `ENABLE_API_DOCS` | Expose `/docs`, `/redoc`, `/openapi.json` (default off) |
| `APPLY_DEBOUNCE_SECONDS` | Batches rapid changes into one apply |

---

## Deploying behind HTTPS

The app speaks plain HTTP and does **not** terminate TLS. Run it behind a reverse proxy
(nginx, Caddy, HAProxy, Traefik…) and let that hold the certificate. Serving it over bare
HTTP puts the admin password and session cookie on the wire in cleartext, which undoes the
lockout and 2FA.

Once a proxy is in front:

```ini
SESSION_HTTPS_ONLY=true    # Secure flag on the session cookie
ENABLE_HSTS=true           # only with a valid cert — browsers cache this
TRUST_PROXY_HEADERS=true   # lockout keys off the real client IP
ENABLE_API_DOCS=false      # keep the admin API surface unlisted
PUBLIC_BASE_URL=https://vpn.example.com   # correct host in one-time links
```

`TRUST_PROXY_HEADERS` is a two-way switch, so set it deliberately:

- **Off** (default) — `X-Forwarded-For` is ignored and lockout keys off the socket address.
  Correct when the app is directly reachable. If it trusted the header here, a client could
  vary it per request and never accumulate failures, walking straight past the lockout.
- **On** — the leftmost `X-Forwarded-For` entry is used. Only correct when a proxy you
  control **overwrites** that header (nginx: `proxy_set_header X-Forwarded-For $remote_addr`).
  A proxy that *appends* to a client-supplied value reintroduces the bypass.

Bind to loopback so the port isn't independently reachable:

```
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Checklist: proxy holds the cert · app on loopback · the five vars above set ·
`SESSION_SECRET` long and random · `ADMIN_PASSWORD_HASH` (not `ADMIN_PASSWORD`) ·
`TOTP_FILE` set so 2FA is available · `.env`, `SETUP_FILE` and the SQLite registry `0600`.

## Project layout

```
app/
  config.py     env-driven settings + pool helpers
  security.py   scrypt hashing, CSRF, login lockout
  models.py     Device + AuditLog (no secrets)
  db.py         engine/session/init
  pfsense.py    async REST API client — the ONLY place the API schema lives
  apply.py      debounced WireGuard apply worker
  ippool.py     collision-safe next-free-IP allocation
  schemas.py    request validation + response models
  hashpw.py     `python -m app.hashpw` password-hash helper
  main.py       FastAPI app, auth gate, security headers, add/import/revoke/state
  templates/    login + dashboard (server-rendered)
  static/       app.js (browser keygen/QR), vendored nacl.min.js + qrcode.js
Dockerfile · docker-compose.yml · .env.example
```

## License

[MIT](LICENSE).

## Not in scope

Access-control automation is intentionally omitted — firewall rules are managed by you in
pfSense. Multi-tunnel support is single-tunnel today. Live handshake/transfer status comes
from the REST API's `command_prompt` endpoint (`wg show`); withhold that privilege from the
API key and everything else still works, peers just show no live status.
