# ARES Terminal Console - Logging, audit and SIEM forwarding

## Streams
| Dataset | What |
|---|---|
| `ares-terminal-console.audit` | security events: sign-in, 2FA, lockout, passwords, users and roles, API tokens, configuration and settings changes, backup and restore |
| `ares-terminal-console.activity` | every state-changing request and every API call (method, path template, status, duration, user or token id) |
| `ares-terminal-console.app` | application log |

Admins see audit and activity under **Admin → Audit & Activity** (filter, export CSV / JSON).
Retention is a setting: audit 365 days and activity 90 days by default. Entries cannot be edited or
deleted; they leave only by retention.

## JSON format
With `LOG_FORMAT=json` (the default everywhere: containers, the `pre` app server and the desktop app)
every event is one JSON object per line on stdout, with ECS-compatible field names. The desktop app also
writes the same lines to `DATA_DIR/logs/ares-terminal-console.jsonl` (rotated at 10 MB, 5 files kept).
`LOG_FORMAT=text` is for a developer terminal only.

```json
{"@timestamp":"2026-11-16T18:00:00.123Z","message":"admin signed in",
 "event":{"kind":"event","dataset":"ares-terminal-console.audit","category":["authentication"],"type":["start"],"action":"login","outcome":"success"},
 "user":{"name":"admin"},"source":{"ip":"203.0.113.7"},"user_agent":{"original":"Mozilla/5.0 …"},
 "http":{"request":{"method":"POST"},"response":{"status_code":303}},"url":{"path":"/login"},
 "service":{"name":"ares-terminal-console","version":"0.1.0","environment":"prod"},"host":{"name":"…"},
 "log":{"level":"info","logger":"ares-terminal-console.audit"},"labels":{"object":"user:admin"}}
```

| Field | Content |
|---|---|
| `@timestamp` | UTC, milliseconds |
| `event.dataset` | `ares-terminal-console.audit`, `ares-terminal-console.activity` or `ares-terminal-console.app` |
| `event.action`, `event.outcome` | what happened; `success`, `failure` or `unknown` |
| `event.category`, `event.type` | ECS categorisation |
| `user.name`, `source.ip`, `user_agent.original` | who and from where |
| `http.*`, `url.path`, `event.duration` | request details (activity: path template, duration in ns) |
| `service.*`, `host.name`, `log.level`, `log.logger` | origin |
| `labels.object`, `labels.token_id` | the object acted on; the API token `id` (never the token) |

Never logged: passwords, tokens, keys, cookies, `Authorization` headers, request bodies.

### Audit actions
Each audit row has a readable action (shown on the Audit page, and as `message`); `event.action` is that
text in lower case with `_` for anything that is not a letter or digit (`Signed in (password)` →
`signed_in_password`). `labels.category` groups them:

| Category | Actions (examples) | `event.category` |
|---|---|---|
| `auth` | signed in (password, LDAP, OIDC, SSO), sign-in failed, sign-in blocked (too many failures), 2FA code accepted / refused, 2FA enabled / disabled, recovery codes regenerated, recovery code used, password changed, password change failed, signed out | `authentication` |
| `admin` | user created / updated / deleted / provisioned from SSO, role synced from SSO groups, password reset, 2FA reset, user signed out, policy changed, SSO / OIDC / LDAP settings changed, audit log exported, terminal ended by an administrator | `iam` / `configuration` |
| `api` | API token created / rotated / revoked, API token rejected, API token lacks scope | `iam` |
| `terminal` | terminal opened (command, label), terminal closed (exit code, duration), command run (the line as recorded in the history: secrets blanked, unechoed input never), local shell refused by policy | `session` |
| `logging` | log forwarding destination added / changed / removed, test event sent | `configuration` |
| `system` | server started / stopped, bootstrap administrator created, backup created / failed / pruned, backup destination tested, restore started / applied, retention purge | `host` / `configuration` |

Outcome: `ok` → `success`; `fail`, `denied`, `error` → `failure` (`denied` also sets `event.type: denied`).
The action's details (`from`/`to` of a change, the reason of a failure) are in `ares-terminal-console.detail`.

## Forwarding
**Admin → Log forwarding** sends events to any number of destinations. For each: type, stream filter
(audit / activity / app), minimum level, enabled, and **Send test event**. Sending never slows the app:
- audit and activity are delivered **at least once**: each destination keeps a cursor and catches up from
  the database after an outage or restart (retry with backoff up to 5 minutes);
- app events use a bounded queue (10,000); when it is full the oldest are dropped and counted.

The page shows sent, failed and dropped counts, the backlog and the last error. TLS certificates are
verified by default. Credentials are stored encrypted. Destination changes, test events and exports are
audited.

| Type | Settings |
|---|---|
| syslog | host, port, UDP / TCP / TLS, facility; RFC 5424, APP-NAME `ares-terminal-console`, the JSON event as the message; octet-counting framing on TCP/TLS |
| HTTP(S) | URL, auth header, batch size, timeout; POST of NDJSON batches (`Content-Type: application/x-ndjson`) |

### From the environment (deploy time)
| Variable | Meaning |
|---|---|
| `LOG_FORMAT` / `LOG_LEVEL` | `json` or `text`; `debug`, `info`, `warn`, `error` |
| `LOG_FORWARD_URL` | `syslog+udp://host:514`, `syslog+tcp://host:601`, `syslog+tls://host:6514` or `https://…` |
| `LOG_FORWARD_AUTH` | HTTP auth header value (secret: `<key>-env` Secret or pm2 `.env`) |
| `LOG_FORWARD_STREAMS` / `LOG_FORWARD_LEVEL` | which of `audit,activity,app`; minimum level forwarded |

It shows on the page read-only, marked "from the environment".

### Examples
| SIEM / collector | Destination |
|---|---|
| Splunk | HTTP(S) `https://<splunk>:8088/services/collector/raw`, header `Authorization: Splunk <HEC token>` |
| Elastic | HTTP(S) to an ingest endpoint or Logstash `http` input, header `Authorization: ApiKey <key>`; fields already match ECS |
| Graylog | HTTP(S) to a GELF HTTP or raw HTTP input, or syslog TCP/TLS to a syslog input with a JSON extractor |
| Loki | HTTP(S) to a Loki-compatible gateway (Promtail / Alloy / Vector HTTP source) |
| Wazuh | syslog TCP/TLS to the manager's `remote` syslog listener; the JSON decoder reads the message |
| Microsoft Sentinel | syslog or HTTP(S) to an AMA / Logstash / Vector collector that forwards to the workspace |
| rsyslog, syslog-ng | syslog UDP/TCP/TLS |

Test with **Send test event**: an `ares-terminal-console.app` event with `event.action` = `test` arrives at the
destination.

### Volume and filters
- `activity` has one event per state-changing request, and every command line sent to a pane is one
  request: an active user produces a few hundred events a day. Terminal output is never logged.
- `audit` is the stream a SIEM should alert on: `sign_in_failed`, `sign_in_blocked_too_many_failures`,
  `2fa_code_refused`, `api_token_rejected`, `admin_access_denied`, user and role changes, and
  `terminal` events for local shells. Forward it at level `info`.
- `app` carries server errors (`error`) and start/stop; `warn` is enough for most collectors.
- The desktop app writes the same events, `service.environment: desktop`, to its own log file.
