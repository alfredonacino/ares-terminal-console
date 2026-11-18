# ARES Terminal Console - Backup and restore

ARES Terminal Console follows the ARES Suite backup standard. This document names **environments, not
servers**: `pre` (Demo, https://ares-terminal-console-demo.nacino.net), `prod` (Production, https://ares-terminal-console.nacino.net) and the desktop app.

## What a backup contains
One archive `ares-terminal-console-backup-<YYYYMMDDTHHMMSSZ>.tar.gz` (UTC), or `.tar.gz.enc` when encrypted, with:
- `manifest.json` (`format: "suite-backup/1"`, key, version, time, and a SHA-256 for every file);
- a consistent snapshot of the database;
- every file under `DATA_DIR` needed to come back, including the app's key files.

Not included: earlier backups, caches and temp files.

For ARES Terminal Console that is:

| In the archive | What it is |
|---|---|
| `db/ares-terminal-console.db` | the SQLite database, through SQLite's online-backup API: users, roles, 2FA secrets (encrypted), recovery-code hashes, API token hashes, sign-in sessions, SSO / LDAP settings (credentials encrypted), policy, audit and activity, log forwarding and backup settings |
| `data/users/<id>/…` | each web user's own data: command and connection history, servers studied by the server tools, the AI cost ledger, and their terminal home (`~/.ssh/known_hosts`, keys they created, shell history) |
| `data/history.json`, `servers.json`, `agent-costs.json` | the same for the desktop app, which has one user |
| `secrets/app_key` | the `APP_KEY` that encrypted the stored credentials (see *Restoring*) |

Left out: earlier backups (`DATA_DIR/backups`), the colour-wrapper directory `bin/` (rebuilt at start),
logs, SSH control sockets, lock and temp files, the one-time `initial-admin-password.txt`, and the backup
passphrase itself. **Running terminals are not in a backup**: a terminal is a live process, and a
restore restarts the server, which ends every session.

## Setting up backups (admins)
Open **Admin → Backup & Restore**.

1. **Passphrase.** Set a backup passphrase. It encrypts every backup with AES-256-GCM and is required
   for remote and S3 destinations. It is **not stored in any backup**: keep it offline (password
   manager, sealed envelope). Without it, nothing can be restored after a total loss.
2. **Destinations**, in any combination:

   | Destination | Settings |
   |---|---|
   | Local | none; kept in `DATA_DIR/backups` |
   | Remote (SSH/SFTP) | host, port, user, directory; password or private key. The host key is pinned on first use. |
   | S3-compatible | endpoint, region, bucket, prefix, access key, secret key, path-style on/off |

   Credentials are stored encrypted by the app and never committed.
3. **Schedule**: off, hourly, every N hours, daily at HH:MM or weekly on a day at HH:MM.
4. **Retention in days** per destination. Older backups are pruned after each successful backup; the
   newest one is always kept. Only `ares-terminal-console-backup-*` files are ever deleted.
5. Click **Back up now** and check that every destination reports success.

The page shows the last backup's time, size and the result per destination. Failures are written to
the audit log and raise the app's alerts. `GET /healthz` does not depend on backup state.

Recommended: in `prod`, an S3 destination as the off-cluster copy; in `pre` and on the desktop,
SSH/SFTP or S3.

## Command line
These work even when the server cannot start:

```bash
python app/main.py backup create                    # one backup to every enabled destination
python app/main.py backup list                      # backups in every destination, newest first
python app/main.py backup restore <file|name>       # restore from a file or a listed backup
python app/main.py backup prune                     # apply each destination's retention now
```

They read the same `DATA_DIR` and `APP_KEY` as the server (`.env` beside the code on `pre`, the
`ares-terminal-console-env` Secret in `prod`). An encrypted backup needs the passphrase:
`--passphrase-file <file>` or `ARES_BACKUP_PASSPHRASE` in the environment, never on the command line.

| Where | How to run them |
|---|---|
| `prod` | `suite kubectl prod -n ares exec deploy/ares-terminal-console-api -- python app/main.py backup list` |
| `pre` | in the app's directory on the app server: `.venv/bin/python app/main.py backup list` |
| Docker | `docker exec <container> python app/main.py backup list` |
| desktop, from source | `DATA_DIR=<the desktop data folder> python3 app/main.py backup list` (folders in `docs/INSTALL.md`) |

## Restoring
From **Backup & Restore → Restore** (upload a file or pick one from a destination), from the
**Restore from backup** button on a fresh install's first-run screen, or with `backup restore`.

The app decrypts the archive, verifies every checksum, checks that the backup belongs to `ares-terminal-console` and
is not newer than the running version, takes a local safety backup of the current state, applies the
backup and reloads. A fresh install keeps its own secret and re-encrypts the restored values with it.

## Disaster recovery runbook
Before you start, have: the backup passphrase, and access to a destination (or a copy of an archive).

### Desktop
1. Install the same or a newer version of ARES Terminal Console (see `docs/INSTALL.md`).
2. Start it and open **Administration → Backup & Restore** (the desktop app has no sign-in), pick the
   archive or a destination, enter the passphrase. Or, before starting it, use `backup restore`.
3. Verify: your saved connections, command history and server history are back.
4. Re-check destinations and schedule under **Backup & Restore** and run **Back up now**.

### `pre` (Demo: pm2 app server)
1. Deploy the same or a newer version: `suite deploy pre`. Wait for its health check to pass.
2. Open https://ares-terminal-console-demo.nacino.net; on the first-run screen choose **Restore from backup**. If the server cannot start,
   run `backup restore <file|name>` in the app's directory on the app server, then
   `suite deploy pre --only server`.
3. Verify: `GET https://ares-terminal-console-demo.nacino.net/healthz`, log in, spot-check data.
4. Re-check destinations and schedule, and run **Back up now**.

### `prod` (Production: Kubernetes)
1. Deploy the same or a newer version: `suite deploy prod` (needs approval). A new PVC `ares-terminal-console-data`
   is created when the old one is gone.
2. Open https://ares-terminal-console.nacino.net; on the first-run screen choose **Restore from backup** and pick the backup from the
   S3 destination (enter its settings and the passphrase). If the server cannot start, run the restore
   in the pod: `suite kubectl prod -n ares exec deploy/ares-terminal-console-api -- python app/main.py backup restore <name>`.
3. Verify: `GET https://ares-terminal-console.nacino.net/healthz`, log in, spot-check data.
4. Re-check destinations and schedule, and run **Back up now**.

### After any restore
- Everyone signs in again: sessions in the backup are ended on restore, and running terminals are gone.
- 2FA keeps working (the secrets are in the database, re-encrypted to this install's `APP_KEY`).
- API tokens from the backup are valid again; revoke any that should not be, under **Admin → API tokens**.
- Single sign-on: if the public address changed, update the redirect URI (Entra ID) or the ACS URL /
  entity ID (SAML) at the identity provider. The LDAP bind password and the OIDC client secret come back
  with the database; if they cannot be decrypted (a backup from an install whose `APP_KEY` was lost),
  enter them again under **Admin → Single sign-on**.
- Log forwarding destinations resume from their stored cursors and send what they missed.
