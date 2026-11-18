# ARES Terminal Console - Deployment

Deployed with the ARES Suite standard. This document names **environments, not servers**:
host names, IPs, users and registry credentials live only in the platform inventory on the
release machine (`~/.claude/platform/infrastructure.json`), never in this repository.

| Environment | URL | Web tier | Server tier |
|---|---|---|---|
| `pre`, Demo | https://ares-terminal-console-demo.nacino.net | Kubernetes (preproduction cluster) | pm2 on the preproduction app server(s), watch on |
| `prod`, Production | https://ares-terminal-console.nacino.net | Kubernetes (production cluster) | Kubernetes |

Where each tier runs is set per environment in the inventory (`placement`). Adding nodes or app
servers is an inventory change only.

## Release flow
```bash
suite doctor                       # standard conformance
suite release                      # tag, images, installers (signed upload), git push, Suite catalog
suite deploy pre                   # demo
suite deploy prod                  # production; needs explicit approval
```

## Preview a deploy
```bash
suite deploy pre --dry-run         # rsync dry run + rendered manifests + kubectl diff
```

## Rollback
- Kubernetes: `kubectl -n ares rollout undo deploy/ares-terminal-console-web` (and `ares-terminal-console-api`), or redeploy the previous tag.
- pm2: check out the previous tag and run `suite deploy pre --only server`.
- Installers: yank the release in the ARES Repository.

## What runs where
| | `pre` | `prod` |
|---|---|---|
| Server (`app/main.py`, port 3222) | pm2 process `ares-terminal-console`, watch on, in the app's directory on each app server; Python virtualenv `.venv` from `requirements.txt` | Deployment `ares-terminal-console-api`, one replica (`maxReplicas: 1`: terminals are processes of that one server, and the database is SQLite), `Recreate` strategy |
| State (`DATA_DIR`) | `data/` beside the code (never rsynced over) | PVC `ares-terminal-console-data` mounted at `/app/data` |
| Secrets | `.env` beside the code, mode 600, generated once by `deploy.sh` (`APP_KEY`), plus `deploy/env.production` | Secret `ares-terminal-console-env`, generated once by `suite deploy` (`APP_KEY`) |
| Web tier | Deployment `ares-terminal-console-web` (nginx) → Service `ares-terminal-console-api` → EndpointSlice of the app server(s) | same image → Service `ares-terminal-console-api` → the api pod |
| Exposure | Edge Proxy Manager route `ares-terminal-console-demo.nacino.net` → `ares-terminal-console-web.ares.svc:80` | Edge Proxy Manager route `ares-terminal-console.nacino.net` → `ares-terminal-console-web.ares.svc:80` |

The web tier forwards WebSockets (the terminals) with a one-hour idle timeout and streams uploads of up
to 4 GB (backup archives to restore). The edge proxy route must allow WebSocket upgrades too.

## First deploy of an environment
1. `suite deploy pre` (or `suite deploy prod`, after approval). The deploy waits for `/healthz`.
2. Add the Edge Proxy Manager route the deploy prints (once per environment), with WebSockets on.
3. Get the one-time password of the first administrator, **`aresadmin`**:
   ```bash
   # prod
   suite kubectl prod -n ares exec deploy/ares-terminal-console-api -- cat /app/data/initial-admin-password.txt
   # pre: in the app's directory on the app server
   cat data/initial-admin-password.txt
   ```
   Or choose it in advance: add `ARES_ADMIN_PASSWORD` to the `ares-terminal-console-env` Secret (prod)
   or to `.env` (pre) **before** the first start. Sign in, change the password, enrol 2FA, delete the file.
4. Configure SSO, backups (an **S3** destination in `prod`), and log forwarding (`docs/ADMIN_GUIDE.md`).
   `LOG_FORWARD_URL` / `LOG_FORWARD_AUTH` in the Secret or `.env` wire a SIEM without clicks.
5. Single sign-on needs the public URLs registered at the identity provider: redirect URI
   `https://<host>/auth/oidc/callback` (Entra ID), ACS `https://<host>/saml/acs` (SAML).

## Upgrades
A deploy restarts the server, which **ends every open terminal** (the processes belong to the server).
Tell users before deploying to `prod`. The database schema is migrated forward at start; take a backup
first (**Admin → Backup & Restore → Back up now**).

## Changing the pm2 log format
`ecosystem.config.cjs` has `time: false` so each line stays one JSON object. pm2 keeps old options on
`startOrReload`: after changing it, run `pm2 delete ares-terminal-console` once on each app server, then
`suite deploy pre`.
