# ARES Terminal Console - API

Everything you can do in the ARES Terminal Console UI is also available as a JSON API under `/api/v1/`.

| Environment | Base URL |
|---|---|
| `prod` | `https://ares-terminal-console.nacino.net/api/v1` |
| `pre` (Demo) | `https://ares-terminal-console-demo.nacino.net/api/v1` |
| desktop | `http://127.0.0.1:<port>/api/v1` while the app runs |

## Tokens
Create a token under **Account → API tokens** (web edition; in the desktop app under **Administration → API tokens**) (admins: **Admin → API tokens** shows every token).

- Format: `ares_<id>_<secret>`. The 8-character `<id>` is public and shown in lists and logs; the
  secret is shown **once**, when you create the token. Store it in a secret manager.
- Scopes: `read`, `write`, `admin`. A token never has more rights than its owner.
- Expiry: 90 days by default, at most 1 year ("never" only for admins). Revoke a token at any time.
- Never put a token in a URL, a script you commit, or a log.
- A token skips 2FA (there is no session to ask) but never its scopes. Creating a token needs a browser
  sign-in: a token cannot create tokens. **Rotate** replaces a token with a new one with the same name,
  scopes and expiry period, and revokes the old one in the same step.

Send it on every request:

```bash
export TOKEN='ares_xxxxxxxx_…'
curl -fsS -H "Authorization: Bearer $TOKEN" https://ares-terminal-console.nacino.net/api/v1/openapi.json
```

## Errors
| Status | Meaning |
|---|---|
| 400 | invalid input; the body says which field |
| 401 | no token, unknown, expired or revoked token |
| 403 | the token lacks the scope, or its owner lacks the role |
| 404 | no such object |
| 429 | too many failed attempts from this IP; retry later |

Errors are JSON: `{"error": "<code>", "message": "<text>"}`. Codes:

| Code | Status | Meaning |
|---|---|---|
| `missing_token`, `invalid_token`, `expired_token`, `revoked_token`, `owner_disabled` | 401 | authentication failed (the response carries `WWW-Authenticate: Bearer`) |
| `insufficient_scope`, `scope_exceeds_role`, `forbidden`, `password_change_required` | 403 | not allowed |
| `invalid_request`, `invalid_scopes`, `invalid_expiry`, `invalid_name` | 400 | bad input |
| `not_found` | 404 | no such object or endpoint |
| `conflict` | 409 | already exists, or a backup is already running |
| `rate_limited` | 429 | too many failed token uses from this address |
| `unavailable` | 501 / 503 | the feature is not available on this install (no PTY, a missing library) |

## Description
`GET /api/v1/openapi.json` returns the OpenAPI 3 description of every endpoint (any scope).

## Endpoints
`GET` needs `read`, anything else `write`; everything under `/api/v1/admin/` needs `admin` (and an
owner who is still an administrator). `openapi.json` and `me` accept any scope. In the commands below
`$U` is `https://ares-terminal-console.nacino.net/api/v1`.

```bash
export U=https://ares-terminal-console.nacino.net/api/v1
H=(-H "Authorization: Bearer $TOKEN")
J=(-H 'Content-Type: application/json')
```

### You
| Method and path | Scope | What |
|---|---|---|
| `GET /me` | any | the token's owner, role, the token's id and scopes |
| `GET /tokens` | read | your tokens (never their secrets) |
| `DELETE /tokens/{id}` | write | revoke one of yours |
| `GET /openapi.json` | any | this API as OpenAPI 3 |

```bash
curl -fsS "${H[@]}" $U/me
```

### Terminals
A terminal's input and output are a WebSocket for the browser and are not part of the API; the API opens,
lists and ends sessions and reads what the app recorded.

| Method and path | Scope | What |
|---|---|---|
| `GET /sessions` | read | your running and recently ended sessions (id, label, command, created, alive, viewers) |
| `POST /sessions` | write | open one: `{"command": "ssh ops@db1", "cwd": "", "cols": 120, "rows": 32, "label": "db1"}`. `command` empty = a local shell, subject to the *local shells* policy |
| `POST /sessions/{id}/kill` | write | end it |
| `GET /history` | read | sessions opened, and saved connections |
| `GET /commands?session=&connection=&q=&limit=` | read | command lines sent, newest first |
| `GET /connections` | read | every SSH destination you connected to, with counts and times |

```bash
curl -fsS "${H[@]}" "$U/commands?connection=ops@db1&limit=50"
curl -fsS -X POST "${H[@]}" "${J[@]}" -d '{"command":"ssh ops@db1","label":"db1"}' $U/sessions
```

### Users (admin)
| Method and path | What |
|---|---|
| `GET /admin/users` | every user, with role, sign-in method, 2FA, last sign-in, online |
| `POST /admin/users` | `{"username","display_name","email","role":"admin\|user","auth_source":"local\|ldap\|oidc\|saml","password"?}`; an empty password generates one (returned once) |
| `PUT /admin/users/{id}` | change `role`, `display_name`, `email`, `disabled`, `auth_source` |
| `DELETE /admin/users/{id}` | delete the account, its tokens and its data |
| `POST /admin/users/{id}/password` | `{"password"?: "", "must_change": true}` |
| `POST /admin/users/{id}/2fa/reset` | remove the user's authenticator and recovery codes |
| `POST /admin/users/{id}/signout` | end every session of that user |
| `GET /admin/sessions?user_id=` · `GET /admin/active` | sign-in history · who is signed in now |
| `GET /admin/terminals` · `POST /admin/terminals/{sid}/kill` | every running terminal with its owner · end one |
| `GET /admin/summary` | counts for the overview |

```bash
curl -fsS -X POST "${H[@]}" "${J[@]}" \
     -d '{"username":"jdoe","display_name":"Jane Doe","email":"jdoe@example.com","role":"user","auth_source":"oidc"}' \
     $U/admin/users
curl -fsS -X POST "${H[@]}" $U/admin/users/7/2fa/reset
```

### Settings (admin)
| Method and path | What |
|---|---|
| `GET /admin/settings` | policy, SSO (OIDC, SAML, LDAP; secrets only as `"set"`), public URL, the SP values |
| `PUT /admin/settings/policy` | e.g. `{"mfa_required":"all","local_shell":"admins","session_idle_minutes":120,"audit_retention_days":365}` |
| `PUT /admin/settings/oidc` · `POST /admin/settings/oidc/test` | Entra ID / OpenID Connect: `{"enabled":true,"provider":"entra","tenant_id":"…","client_id":"…","client_secret":"…","admin_groups":["<object id>"]}` |
| `PUT /admin/settings/saml` · `POST /admin/settings/saml/metadata` | SAML; `metadata` parses `{"url": "…"}` or `{"xml": "…"}` without saving |
| `PUT /admin/settings/ldap` · `POST /admin/settings/ldap/test` | LDAP / AD: `{"server_url":"ldaps://dc1.example.com","bind_dn":"…","bind_password":"…","base_dn":"…"}`; `test` takes an optional `{"username","password"}` |

A secret field (`client_secret`, `bind_password`) left out keeps the stored value; `""` removes it.

```bash
curl -fsS -X PUT "${H[@]}" "${J[@]}" -d '{"mfa_required":"all","local_shell":"admins"}' $U/admin/settings/policy
```

### Audit and activity (admin)
| Method and path | What |
|---|---|
| `GET /admin/audit?since=&until=&username=&action=&outcome=&category=&q=&limit=&before_id=` | audit events, newest first (`since`/`until` in epoch seconds; page with `before_id`) |
| `GET /admin/activity?…&method=&path=` | activity events |
| `GET /admin/audit.csv` · `audit.json` · `activity.csv` · `activity.json` | the filtered view, at most 5,000 rows (JSON is NDJSON, one ECS event per line). Exports are audited |
| `GET /admin/tokens` · `DELETE /admin/tokens/{id}` | every user's tokens · revoke any |

```bash
curl -fsS "${H[@]}" "$U/admin/audit.json?since=$(date -d '1 day ago' +%s)" > audit.ndjson
```

### Log forwarding (admin)
| Method and path | What |
|---|---|
| `GET /admin/logging` | destinations with sent / failed / dropped counts, backlog, last error |
| `POST /admin/logging/destinations` | `{"name":"Splunk","type":"http","url":"https://splunk.example.com:8088/services/collector/raw","auth_header":"Authorization: Splunk <HEC token>","streams":["audit","activity"],"min_level":"info"}` or `{"type":"syslog","host":"…","port":6514,"transport":"tls"}` |
| `PUT /admin/logging/destinations/{id}` · `DELETE …/{id}` | change · remove |
| `POST /admin/logging/destinations/{id}/test` | send one test event |

### Backup and restore (admin)
| Method and path | What |
|---|---|
| `GET /admin/backup` | passphrase set or not, schedule, destinations and their last result, history |
| `PUT /admin/backup/passphrase` | `{"passphrase": "<12+ characters>"}`; `""` removes it |
| `PUT /admin/backup/schedule` | `{"mode":"daily","time":"02:30"}`; modes `off`, `hourly`, `every` (+`hours`), `daily`, `weekly` (+`weekday` 0=Mon) |
| `POST /admin/backup/destinations` | SFTP `{"type":"sftp","name","host","port","username","directory","password"\|"private_key","retention_days"}` or S3 `{"type":"s3","name","endpoint","region","bucket","prefix","access_key","secret_key","path_style","retention_days"}` |
| `PUT` · `DELETE /admin/backup/destinations/{id}` · `POST …/{id}/test` | change · remove · test (pins an SFTP host key on first use) |
| `GET /admin/backup/destinations/{id}/backups` · `GET …/backups/{name}` | list · download one archive |
| `POST /admin/backup/run` | back up now (`{"destinations": [ids]}` optional); waits for the result |
| `POST /admin/backup/prune` | apply retention now |
| `POST /admin/backup/upload` | raw body (`application/octet-stream`, header `X-Filename`): returns an upload id |
| `POST /admin/backup/restore` | `{"upload": id}` or `{"destination": id, "name": file}`, plus `"passphrase"`; verifies, takes a safety backup, restarts the server |

```bash
curl -fsS -X POST "${H[@]}" $U/admin/backup/run
curl -fsS "${H[@]}" $U/admin/backup/destinations/local/backups
curl -fsS -X POST "${H[@]}" "${J[@]}" \
     -d '{"destination":"local","name":"ares-terminal-console-backup-20261118T023000Z.tar.gz.enc","passphrase":"…"}' \
     $U/admin/backup/restore
```

`GET /api/v1/openapi.json` is the authoritative list for the version you are talking to.

## Audit
Every API call is written to the activity log with the token's `id`, and every failed token use to
the audit log (see `docs/LOGGING.md`).
