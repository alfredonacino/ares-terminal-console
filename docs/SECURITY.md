# ARES Terminal Console - Security

A terminal is remote code execution by design. This page says exactly who gets it, as whom, and what
protects the way in.

## Two editions, two trust models
| | Desktop app, `./run.sh`, ApexBuild | Web edition (`prod`, `pre`, Docker) |
|---|---|---|
| Sign-in | none: it is one person's terminal on their own computer | required: local users, LDAP, Entra ID (OIDC) or SAML, with 2FA |
| Listens on | `127.0.0.1` only. The desktop app also requires a random access token (in an HttpOnly cookie), because every other user on a shared machine can reach a loopback port | `0.0.0.0` behind the suite's web tier and edge proxy, which terminate TLS |
| Shells run as | you | the server's service account (`app`, uid 10001, in the container; the deploy user on the `pre` app server) |

## What a web user can reach
- **SSH panes**: `ssh` runs on the app's server and connects onwards with the user's own credentials,
  typed in the pane. Known hosts and any keys a user creates live in **their own** home directory
  (`DATA_DIR/users/<id>/home`), not shared with other users.
- **Local shells** run on the server that hosts the app, as its service account: they can read whatever
  that account can, including the app's `DATA_DIR`. They are therefore **administrators only by default**
  (policy *Local shells*: administrators / everyone / nobody). A user without local shells can only open
  `ssh` panes; the command is parsed (no shell), must be `ssh`, and options that would run local commands,
  read local files or open listening ports are refused (`-o`, `-F`, `-J`, `-S`, `-L`, `-R`, `-D`, `-W`, `-w`,
  `-i`, `-I`, `-E`, `-e`, `-f`, `-N`, `-M`, `-O`; only `-4 -6 -a -A -b -B -c -C -g -k -K -l -m -p -P -q -Q -s
  -t -T -v -V -x -X -y -Y` are accepted). Their `ssh` is then pinned to their own (empty) config, known_hosts
  and identity file, with no SSH agent, no forwarding and escape characters off (`-e none`), so it can never
  use the service account's keys. The server tools are limited to their SSH panes too.
- **Connection sharing is per user.** SSH multiplexing (ControlMaster) sockets are in a directory per user,
  so one user's authenticated connection to a host is never reused by another user's `ssh`.
- In `prod` the shells run inside the `ares-terminal-console-api` pod: non-root, all capabilities dropped,
  RuntimeDefault seccomp, no privilege escalation, no service account token used by the app. What a pane can
  reach on the network is what that pod can reach: restrict it with a NetworkPolicy if needed.
- Each user's terminals, scrollback, command history, connection history and server tools data are
  separate. A WebSocket only attaches to a pane its own user opened; ending a user's session (sign-out,
  disable, password reset, an admin's *Sign out everywhere*) closes their live terminal connections at once.
- Every terminal opened and closed, and every command line sent, is in the audit log with who and from
  where (passwords that were not echoed are never recorded, and `--password`-style arguments are blanked).

## Authentication
- **Passwords**: scrypt (N=2^15, r=8, p=1), at least 12 characters with three character classes, not
  containing the username. A wrong username costs the same time as a wrong password.
- **Lockout**: failures per username and per source address, configurable (default 8 in 15 minutes).
- **2FA**: TOTP (RFC 6238, SHA-1, 6 digits, 30 s, ±1 step), the secret stored encrypted with `APP_KEY`;
  a code is accepted once (no replay within its window). Ten single-use recovery codes, stored as SHA-256
  hashes. Required for every local and LDAP account by default.
- **Entra ID / OIDC**: authorization code flow with PKCE (S256), `state` and `nonce`; the ID token's
  signature (RS256/ES256 from the provider's JWKS), issuer, audience, expiry and nonce are verified.
- **SAML 2.0**: signed responses or assertions only (signxml, no XML entity expansion), audience,
  recipient, `InResponseTo` and validity window checked, every assertion ID accepted once.
- **LDAP**: LDAPS or StartTLS with certificate verification; user input is escaped into the filter; an
  empty password is always refused (it would be an anonymous bind).
- **Sessions**: a random 256-bit cookie value; only a keyed hash of it is stored. Cookie `HttpOnly`,
  `SameSite=Strict`, and `Secure` with the `__Host-` prefix exactly when the request came over TLS
  (directly or `X-Forwarded-Proto: https` from the web tier). Idle and absolute timeouts.
- **CSRF**: state-changing browser requests must be same-origin (`Origin` / `Sec-Fetch-Site`), and the
  terminal WebSocket checks `Origin` on the handshake.

## API tokens
`ares_<id>_<secret>`: 32 bytes from the OS CSPRNG. Only SHA-256(secret) is stored, compared in constant
time, shown once. Scopes `read`, `write`, `admin`, never above the owner's current role; expiry 90 days by
default, at most one year ("never" only by an admin). Failed uses are rate-limited per source address and
audited by token id only. Tokens never appear in logs, URLs or audit details. See `docs/API.md`.

## Secrets and stored credentials
- Never committed. `APP_KEY` is generated once on the first deploy (pm2 `.env`, mode 600; the
  `ares-terminal-console-env` Secret in Kubernetes) and never rotated automatically.
- LDAP bind password, OIDC client secret, TOTP secrets, backup destination and log destination
  credentials are sealed with AES-256-GCM under keys derived from `APP_KEY` (HKDF).
- Backups to SFTP and S3 must be encrypted (AES-256-GCM, scrypt-derived key); the passphrase is never in a
  backup. See `docs/BACKUP.md`.
- CI secrets are group-level masked variables. The Repository signing key stays on the release machine.

## Hardening built in
- Containers run as non-root with all capabilities dropped and a RuntimeDefault seccomp profile.
- Strict Content-Security-Policy (`script-src 'self'`, no inline scripts), `frame-ancestors 'self'`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` on pages
  and API answers.
- Request bodies are size-limited; static files are served only from the app's own folder.
- Security events go to the append-only audit log (who, what, object, outcome, IP, user agent) and can
  be forwarded to a SIEM (`docs/LOGGING.md`). Passwords, tokens, keys, cookies and request bodies are
  never logged.

## Reporting a vulnerability
Write to the ARES Suite maintainers through the project's GitLab issue tracker, marked confidential, or
privately to the address in the ARES Suite portal's About page. Please do not open a public issue.
