# ARES Terminal Console: Technical Blueprint

This blueprint is the engineering drawing set for ARES Terminal Console 2.4: one sheet per concern, each with the diagram and the rules an implementer or reviewer needs. The Architecture document explains *why*; these sheets say *exactly how*.

## Runtime topology

One server process owns every terminal. In `prod` it is a single Kubernetes pod with a persistent volume; in `pre` it is a pm2 process on the preproduction app server behind the same nginx web tier. The desktop app runs the same server on loopback, without sign-in.

```mermaid
%% caption: The three ways the same server runs
flowchart LR
  B["Browser"] -->|HTTPS + WebSocket| E["Edge proxy"]
  E --> W["ares-terminal-console-web<br/>nginx"]
  W -->|"http://ares-terminal-console-api:3222"| S["app/main.py<br/>users mode"]
  S --> D[("DATA_DIR<br/>SQLite + per-user data")]
  S --> P["PTYs<br/>bash · ssh"]
  DW["Desktop window<br/>Qt / WebView"] -->|"loopback + access token"| L["same server<br/>local mode"]
  L --> P2["PTYs"]
```

| Tier | `prod` | `pre` | Desktop |
|---|---|---|---|
| Web | nginx Deployment, production cluster | nginx Deployment, preproduction cluster | none |
| Server | Deployment `ares-terminal-console-api`, 1 replica, `Recreate` | pm2 `ares-terminal-console`, watch on | in-process |
| State | PVC `ares-terminal-console-data`, 5 Gi | `data/` beside the code | the user's profile |
| Sign-in | required | required | none |

## Request authentication

Every request is identified once, then everything it touches resolves to that user. Bearer tokens and session cookies are the only two ways in; `/healthz`, `/login` and the SSO endpoints are the only anonymous routes.

```mermaid
%% caption: How a request becomes a user
flowchart TD
  R["request"] --> H{"Authorization:<br/>Bearer ares_…?"}
  H -->|yes| T["look up id · SHA-256(secret)<br/>constant-time compare"]
  T --> SC{"scope ≥ route<br/>and ≤ owner role?"}
  H -->|no| C{"session cookie?"}
  C -->|yes| K["keyed hash → session<br/>idle / absolute expiry"]
  K --> M{"2FA done?<br/>password current?"}
  C -->|no| A["401 / redirect to /login"]
  SC -->|yes| U["user context"]
  M -->|yes| X{"same origin?<br/>(state-changing)"}
  X -->|yes| U
```

| Check | Rule |
|---|---|
| Token | `ares_<8 hex>_<43 base64url>`; skips CSRF and 2FA, never scopes; failures rate-limited per IP |
| Session | 256-bit random value; only HMAC stored; `HttpOnly`, `SameSite=Strict`, `__Host-`/`Secure` over TLS |
| CSRF | `Origin` or `Sec-Fetch-Site` must be same-origin on every non-GET and on the WebSocket handshake |
| Lockout | per username and per source address, default 8 failures in 15 minutes |

## Sign-in methods

Four sources feed one user table. Local accounts are always checked first, so the bootstrap administrator `aresadmin` works when the directory or identity provider does not.

```mermaid
%% caption: Sign-in sources and where 2FA applies
flowchart LR
  F["username + password"] --> LOC["local: scrypt"]
  F --> LD["LDAP / AD: service bind,<br/>escaped search, user bind"]
  O["Sign in with Microsoft"] --> OI["OIDC: code + PKCE,<br/>JWKS-verified ID token"]
  S["SSO button"] --> SA["SAML 2.0: signed POST,<br/>one-time assertion ID"]
  LOC --> MFA{"TOTP required?"}
  LD --> MFA
  OI --> G["groups → role"]
  SA --> G
  G --> MFA2{"policy: also for SSO?"}
  MFA --> OK["session"]
  MFA2 --> OK
```

| Source | Groups | Provisioning |
|---|---|---|
| Local | role set by an admin | created by an admin |
| LDAP | `memberOf` DNs | on first sign-in, if auto-provision |
| Entra ID | group object IDs or app roles | on first sign-in, if auto-provision |
| SAML | groups attribute | on first sign-in, if auto-provision |

## Terminal isolation

A terminal is a PTY owned by the server, tagged with its owner. A WebSocket can only attach to a session its user opened, and it is registered against the sign-in session that opened it, so signing that session out closes the socket at once.

```mermaid
%% caption: Ownership of a terminal
flowchart LR
  U1["user 7"] -->|"POST /api/sessions"| PS["PTY session<br/>owner = 7"]
  PS --> HOME["HOME = DATA_DIR/users/7/home"]
  U1 -->|"WS attach"| PS
  U2["user 9"] -.->|"403"| PS
  ADM["admin"] -->|"Admin → Active now: kill"| PS
```

| Policy *local shells* | Admin | User |
|---|---|---|
| `admins` (default) | any command | parsed `ssh` only; `-o -F -S -L -R -D -W -i -E -f -N -M -O` refused |
| `all` | any command | any command |
| `none` | parsed `ssh` only | parsed `ssh` only |

## Data layout

All state lives under `DATA_DIR`. The database is SQLite in WAL mode; terminal history stays in small JSON files per user.

| Path | Content |
|---|---|
| `ares-terminal-console.db` | users, sessions, tokens, settings, audit, activity, SSO request state |
| `users/<id>/` | history, servers, AI cost ledger, terminal `home/` |
| `.app_key` | `APP_KEY` when not supplied by the environment |
| `backups/` | local backup destination |
| `logs/ares-terminal-console.jsonl` | rotated JSON log (desktop) |
| `initial-admin-password.txt` | one-time `aresadmin` password, deleted after first use |

> **Note:** Sealed values (TOTP secrets, LDAP bind password, OIDC client secret, backup and log destination credentials) are AES-256-GCM under keys derived from `APP_KEY` with HKDF.

## Backup and restore

A backup is one `suite-backup/1` archive with a manifest of checksums, a consistent SQLite snapshot and the data folder. Remote and S3 copies are always encrypted.

```mermaid
%% caption: Backup pipeline and restore checks
flowchart LR
  DB[("SQLite")] -->|"online backup API"| SN["snapshot"]
  DATA["DATA_DIR files"] --> TAR["tar.gz + manifest.json"]
  SN --> TAR
  TAR -->|"AES-256-GCM<br/>scrypt passphrase"| ENC[".tar.gz.enc"]
  ENC --> LOC["local"]
  ENC --> SFTP["SFTP"]
  ENC --> S3["S3"]
  ENC -->|"restore"| V{"checksums, key,<br/>version ok?"}
  V -->|yes| SAFE["safety backup"] --> APPLY["apply + restart"]
```

| Rule | Value |
|---|---|
| Name | `ares-terminal-console-backup-<YYYYMMDDTHHMMSSZ>.tar.gz[.enc]` |
| Schedule | off, hourly, every N hours, daily, weekly; one replica runs it |
| Retention | days per destination; the newest backup is always kept |
| CLI | `python app/main.py backup create \| list \| restore <file\|name> \| prune` |

## Logs and SIEM

Three streams, one ECS JSON object per line. Audit and activity are delivered at least once from a database cursor; app events use a bounded queue that drops and counts rather than block a request.

```mermaid
%% caption: Event streams and forwarding
flowchart LR
  REQ["requests"] --> ACT["activity"]
  SEC["security events"] --> AUD["audit"]
  APP["server"] --> AP["app"]
  ACT --> DBL[("database")]
  AUD --> DBL
  DBL -->|"cursor"| FW["forwarders"]
  AP -->|"bounded queue"| FW
  ACT --> OUT["stdout JSON"]
  AUD --> OUT
  AP --> OUT
  FW --> SY["syslog RFC 5424<br/>UDP / TCP / TLS"]
  FW --> HT["HTTPS NDJSON<br/>Splunk · Elastic · Loki"]
```

| Dataset | Content |
|---|---|
| `ares-terminal-console.audit` | sign-in, 2FA, users and roles, tokens, settings, backup, terminals and commands |
| `ares-terminal-console.activity` | method, path template, status, duration, user or token id |
| `ares-terminal-console.app` | start, stop, errors |

## Release and deployment

One tag produces every artifact. Images and installers carry the version from `VERSION`.

```mermaid
%% caption: From tag to environments
flowchart LR
  TAG["git tag v2.4.0"] --> GL["GitLab CI<br/>tests + images"]
  TAG --> GH["GitHub Actions<br/>desktop matrix"]
  GL --> REG["docker.cybercontrol.tech/ares/<br/>ares-terminal-console[-web]"]
  GH --> INS["deb · rpm · pkg.tar.zst · AppImage · tar.gz<br/>setup.exe · msi · zip · dmg"]
  INS -->|"apexctl, signed"| REPO["ARES Repository"]
  REG --> PRE["suite deploy pre"]
  REG --> PROD["suite deploy prod"]
```
