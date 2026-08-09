# pfSense setup: service account, privileges, and API key

This app talks to pfSense exclusively through the
[pfSense REST API package](https://github.com/pfrest/pfSense-pkg-RESTAPI) (v2). This guide
creates a **dedicated service account** with the minimum privileges the app needs, rather
than pointing it at an `admin` key.

Using an admin key works, but it means a compromise of this app's `.env` is a full
compromise of your firewall. The account below can manage WireGuard peers and the traffic
shaper, and can do nothing else — no users, no certificates, no shell, no firewall settings.

**Requires REST API package v2.9.0 or newer.** Earlier versions lack
`/api/v2/status/wireguard/peers`, and the app would have to fall back to a root shell
command for live peer status. See [Older package versions](#older-package-versions).

---

## 1. Create the user

**System → User Manager → Add**

| Field | Value |
|---|---|
| Username | `wg-web` (any name; it is referenced nowhere in the app) |
| Password | a long random string — see [Password](#the-password-and-why-it-matters) |
| Group membership | none |
| Shell access | **leave unchecked** |
| Certificate | none |

Do **not** add it to `admins`.

## 2. Assign privileges

**System → User Manager → `wg-web` → Effective Privileges → Add**

The REST API package generates one privilege per endpoint *and method*. They are listed as
`REST API - /api/v2/... METHOD`; filtering the list on `REST API -` makes them easy to find.

Assign these 22:

### WireGuard peers — the core of the app

| Privilege | Purpose |
|---|---|
| `api-v2-vpn-wireguard-tunnels-get` | discover tunnels (used by the setup wizard) |
| `api-v2-vpn-wireguard-peers-get` | list peers |
| `api-v2-vpn-wireguard-peer-post` | create a peer |
| `api-v2-vpn-wireguard-peer-patch` | edit / re-key a peer |
| `api-v2-vpn-wireguard-peer-delete` | revoke a peer |
| `api-v2-vpn-wireguard-apply-post` | apply pending WireGuard changes |
| `api-v2-vpn-wireguard-apply-get` | read pending-change state |
| `api-v2-status-wireguard-peers-get` | live handshake / transfer counters |

### Traffic shaping — only if you use the QoS features

Skip this block entirely if you do not use the shaper; the app degrades gracefully.

| Privilege | Purpose |
|---|---|
| `api-v2-interfaces-get` | list interfaces to shape |
| `api-v2-firewall-rules-get` | find rules to attach limiters to |
| `api-v2-firewall-rule-patch` | set `dnpipe` / `pdnpipe` on a rule |
| `api-v2-firewall-apply-post` | apply pending firewall changes |
| `api-v2-firewall-traffic-shaper-limiters-get` | list limiters |
| `api-v2-firewall-traffic-shaper-limiter-post` | create a limiter |
| `api-v2-firewall-traffic-shaper-limiter-delete` | remove a limiter |
| `api-v2-firewall-traffic-shaper-limiter-bandwidth-patch` | adjust bandwidth |
| `api-v2-firewall-traffic-shaper-limiter-queue-post` | create a queue |
| `api-v2-firewall-traffic-shaper-limiter-queue-patch` | adjust queue weight |

### Self-service key rotation — optional

Only if you want the account to be able to reissue its own API key. See
[Rotating the API key](#rotating-the-api-key).

| Privilege | Purpose |
|---|---|
| `api-v2-auth-key-post` | mint a replacement key for itself |
| `api-v2-auth-key-delete` | revoke a key by id |
| `api-v2-auth-keys-get` | look up the id of the key being replaced |

> **Note:** key *deletion* is not scoped to the calling user — an account holding
> `api-v2-auth-key-delete` can revoke other users' keys. If that matters in your
> environment, grant only `api-v2-auth-key-post` and revoke old keys manually as an admin.

### What NOT to grant

- **`page-all`** ("WebCfg - All pages") — grants the entire API. Defeats the purpose.
- **`api-v2-diagnostics-command-prompt-post`** — runs arbitrary shell commands **as root**
  on your firewall. The app has not needed this since it moved to
  `/api/v2/status/wireguard/peers`. Never grant it to a service account.
- **`user-shell-access`** — unnecessary; this account never logs in interactively.

### Deriving privilege names yourself

If you need a privilege this guide does not list, you can derive its name from the endpoint
URL: replace `/` and `_` with `-`, drop the leading `-`, and append the lowercased method.

```
PATCH /api/v2/firewall/traffic_shaper/limiter
      -> api-v2-firewall-traffic-shaper-limiter-patch
```

## 3. Create the API key

**System → REST API → Keys → Add**, while logged in **as that user**.

A key always belongs to the account that creates it — the API forces the owner to the
authenticating user, so you cannot mint a key for someone else. The key is displayed
**once**; copy it immediately.

Then put it in the app's `.env` (or enter it in the first-run wizard):

```ini
PFSENSE_API_URL=https://192.0.2.1
PFSENSE_API_KEY=<the key you just copied>
```

Make sure `.env` is `0600` and owned by the user the app runs as.

Also confirm **System → REST API → Settings** has the **Key** authentication method
enabled, that your app's source interface is permitted under *Allowed Interfaces*, and that
*read-only mode* is off.

---

## Verifying the privileges

Every write endpoint accepts a `Prefer: dry-run` header: the request is fully authenticated
and validated, but nothing is written and no apply runs. Authorization is checked *before*
the target object is looked up, so any response that is not `401`/`403` means the privilege
is present.

```bash
KEY=<your key>; PF=https://192.0.2.1

# read check
curl -sk -o /dev/null -w '%{http_code}\n' -H "X-API-Key: $KEY" \
  "$PF/api/v2/status/wireguard/peers?limit=0"          # expect 200

# write check — validates only, changes nothing
curl -sk -o /dev/null -w '%{http_code}\n' -X PATCH \
  -H "X-API-Key: $KEY" -H 'Prefer: dry-run' -H 'Content-Type: application/json' \
  -d '{"id":0,"enabled":true}' "$PF/api/v2/vpn/wireguard/peer"   # expect 200 (or 404)

# negative check — this MUST fail
curl -sk -o /dev/null -w '%{http_code}\n' -X POST \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"command":"id"}' "$PF/api/v2/diagnostics/command_prompt"  # expect 403
```

---

## The password, and why it matters

The account's password is **not** used for day-to-day operation — the app authenticates
only with `X-API-Key`. It matters for exactly one thing: **creating and revoking API keys
requires HTTP Basic authentication.** The key endpoints accept Basic auth only, so an API
key can never mint its own replacement.

Consequences:

- Rotating the password does **not** disturb a running deployment. Key authentication is
  validated against a stored hash of the key, independently of the password.
- Any automated key rotation must have the account's password available to it. Store it
  wherever that job runs, not in the app's `.env`.
- If you never intend to rotate keys via the API, the password can be a throwaway you
  discard after creating the key in the UI.

## Rotating the API key

Because keys are additive and revocation is separate, rotation is zero-downtime: mint the
new key, cut over, then revoke the old one.

```bash
PF=https://192.0.2.1; USER=wg-web

# 1. mint a replacement (Basic auth — an API key will NOT work here)
curl -sk -u "$USER" -X POST -H 'Content-Type: application/json' \
  -d '{"descr":"wg-web '"$(date +%F)"'"}' "$PF/api/v2/auth/key"

# 2. put the returned `key` into .env, restart the app, confirm it is healthy

# 3. find the old key's id, then revoke it
curl -sk -u "$USER" "$PF/api/v2/auth/keys?limit=0"
curl -sk -u "$USER" -X DELETE "$PF/api/v2/auth/key?id=<old id>"
```

> **Key ids are positional and renumber when a key is deleted.** Always look a key up by its
> description or username immediately before revoking it — never hardcode an id.

---

## Older package versions

On REST API package versions before **v2.9.0** there is no
`/api/v2/status/wireguard/peers`, and the only way to read live handshake and transfer
counters is `wg show`, via `POST /api/v2/diagnostics/command_prompt` — which pfSense
executes **as root**.

Granting that to a service account hands it full control of the firewall, which undoes the
point of this guide. Prefer to upgrade the package. If you cannot, the app still runs
without the privilege: peers simply show no live status, and the dashboard's online counts
and throughput graph stay empty.

## A note on preshared keys

The REST API marks preshared keys `sensitive`, so it redacts them on **every** endpoint —
they can be written but never read back. Because of this, re-keying a device issues a
**fresh** preshared key and writes it to the peer along with the new public key, so both
ends stay in sync from the single reissued config.

Two practical consequences: a peer that had no preshared key gains one when re-keyed, and a
reissued config must be used in full — pasting only the new private key into an old config
file leaves a stale preshared key and the handshake will fail.
