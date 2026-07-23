# Security Policy

## Reporting a vulnerability

Please report security issues **privately** — open a
[GitHub security advisory](https://github.com/nath2125/wg-webgui-pfsense/security/advisories/new)
rather than a public issue, so a fix can land before the details are public.

Useful detail: affected version or commit, what an attacker can achieve, and the smallest
set of steps that demonstrates it.

## Supported versions

The latest release on `main` is the only supported version. This is a small self-hosted
project, so fixes land in a new release rather than being backported.

## What this app is trusted with

It holds a **pfSense REST API key** with enough authority to add, change and remove
WireGuard peers, and it can reach a diagnostics endpoint that runs commands on the firewall.
Anyone who reaches the admin session effectively controls WireGuard on that firewall. Treat
it as infrastructure, not as a public web app:

- Never expose it directly to the internet. Put it on a management network or behind a VPN.
- Serve it over HTTPS behind a reverse proxy — see "Deploying behind HTTPS" in the README.
- Enable TOTP 2FA (`TOTP_FILE`) and use `ADMIN_PASSWORD_HASH` rather than a plaintext password.
- Scope the pfSense API key to the WireGuard endpoints it actually needs.

## Design notes relevant to security

- **Client private keys never reach the server.** Keypairs are generated in the browser; the
  server only ever sees public keys. There is no server-side copy of a client config, so a
  compromise of this app cannot reveal existing clients' private keys.
- **The registry stores no secrets** — device names, public keys, assigned IPs, audit rows.
- **One-time config links** are encrypted with a key derived from the link token. The token
  is never stored and lookup uses a separate hash, so the database alone cannot decrypt a
  pending config. Links are single-use and expiring.
- **The pfSense API key** is read from the environment or a `0600` setup file, is never
  logged, and is never returned by any endpoint.

## Out of scope

- **Firewall/access rules.** This app manages peers and routing (`AllowedIPs`), not access
  control. What a peer may reach is governed by pfSense firewall rules, which are yours to
  set — see "Not in scope" in the README.
- Anything requiring an already-authenticated admin session is generally *not* a
  vulnerability, since that session is the app's trust boundary. Exceptions worth reporting:
  privilege escalation beyond WireGuard management (e.g. command execution on the firewall
  or the host), disclosure of the API key or a client private key, or CSRF/XSS that lets an
  unauthenticated party act through an admin's session.
