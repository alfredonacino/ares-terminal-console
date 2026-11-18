# ARES Terminal Console - Administration

This guide is for the **web edition** (`prod`: https://ares-terminal-console.nacino.net, `pre`:
https://ares-terminal-console-demo.nacino.net, or your own Docker container). The desktop app has no
sign-in and no users: it is one person's terminal on their own computer. Its **Administration** page
only has Backup & Restore, Audit & Activity, Log forwarding and API tokens.

## First sign-in: `aresadmin`
A new installation creates one administrator, **`aresadmin`**, the first time it starts:

- With `ARES_ADMIN_PASSWORD` set (the `ares-terminal-console-env` Secret in `prod`, the `.env` on `pre`),
  that is its password.
- Otherwise a random one-time password is written to `DATA_DIR/initial-admin-password.txt` (mode 600).
  Read it where the server runs (`docs/DEPLOYMENT.md` has the exact commands), sign in, choose a new
  password, then enrol two-factor authentication. Delete the file afterwards; it is never in a backup.

`ARES_ADMIN_USER` changes the name of that first account; it is only read when the database has no users.
The first-run screen also offers **Restore from a backup**, to bring back an earlier installation instead.

## Configuration
Settings made in the UI live in the database. These come from the environment. Secrets are generated
once on the first deploy and never rotated automatically (the pm2 `.env` in `pre`; the
`ares-terminal-console-env` Secret in `prod`).

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `3222` | listen port |
| `HOST` | `0.0.0.0` | listen address |
| `DATA_DIR` | `./data` (`/app/data` in containers) | all state: database, users' data, local backups |
| `APP_KEY` | generated (`DATA_DIR/.app_key` when unset) | encrypts stored credentials (2FA secrets, SSO and LDAP secrets, backup and log destination credentials). **Secret.** Never change it by hand: a backup restore re-encrypts to the current key |
| `ARES_ADMIN_USER` / `ARES_ADMIN_PASSWORD` | `aresadmin` / random | the first administrator (see above). The password is a secret |
| `ARES_PUBLIC_URL` | from the request | the public address (`https://host`), used for SSO redirect and ACS URLs. Set it when the proxy chain hides the real host |
| `ARES_TRUST_PROXY` | `1` | take the client IP and scheme from `X-Forwarded-For` / `X-Forwarded-Proto` (the web tier sets them). Set `0` when the server is reached directly |
| `ARES_ENVIRONMENT` | `prod` / `pre` / `desktop` | `service.environment` in the logs |
| `LOG_FORMAT`, `LOG_LEVEL`, `LOG_FORWARD_*` | `json`, `info` | see `docs/LOGGING.md` |
| `PINGMORA_HEALTH_TOKEN` | unset | optional Bearer token (at least 32 characters) that lets APEX Pingmora read the details of `GET /healthz/pingmora`; unset = only API tokens with the `read` scope. **Secret.** See `docs/API.md` |

## Users
**Admin → Users** lists every account with its role, sign-in method, 2FA state, last sign-in and whether
it is online now.

| Action | Notes |
|---|---|
| Add user | username, display name, email, role, sign-in method (`local`, `ldap`, `oidc`, `saml`). A local account gets the password you type or a generated one (shown once) and must change it at first sign-in |
| Edit | role, display name, email, disable / enable. Disabling ends the user's sign-in sessions and closes their terminals' browser connections at once |
| Reset password | local accounts; the user must change it at next sign-in, their other sessions end |
| Reset 2FA | removes the authenticator and recovery codes; the user enrols again at next sign-in (use it for a lost phone) |
| Sign out everywhere | ends every session of that user |
| Delete | removes the account, its API tokens and its data folder (history, terminal home). The audit log keeps what it did |

Roles:

| Role | Can |
|---|---|
| `admin` | everything, including every Admin page, and open **local shells** on the server |
| `user` | terminals to servers over SSH; local shells only when the policy allows (see *Policy*) |

The last active administrator cannot be demoted, disabled or deleted.

Each user's terminals, command history, connection history and server tools data are their own: a user
never sees another user's panes. Admins can list every running terminal (owner, command, since when) under
**Admin → Active now** and end one.

## Two-factor authentication
TOTP (RFC 6238): any authenticator app (Microsoft Authenticator, Google Authenticator, 1Password,
Bitwarden, FreeOTP…). A user enrols by scanning the QR code shown after sign-in (or typing the secret)
and confirming one code; they then get **10 one-time recovery codes**, shown once. Each recovery code
works once in place of a code.

**Admin → Policy → Two-factor authentication**:

| Setting | Effect |
|---|---|
| Required for everyone (default) | every local and LDAP account must enrol before it can open a terminal |
| Required for administrators | admins must, users may |
| Optional | users choose under **Account → Two-factor authentication** |
| Also for SSO accounts | off by default: Entra ID and SAML accounts rely on the identity provider's MFA (Conditional Access). Turn it on to ask for this app's code as well |

API tokens never ask for a code (there is no session); they are limited by their scopes instead.

## Policy
**Admin → Policy**:

| Setting | Default |
|---|---|
| Session idle timeout / maximum length | 120 minutes / 12 hours |
| Lockout | 8 failed sign-ins in 15 minutes locks that username (and a source address after 3× as many) for 15 minutes |
| Password sign-in | enabled for everyone, or limited to administrators (everyone else uses SSO) |
| Local shells | **administrators only** (default), everyone, or nobody. Without it a user can only open `ssh` connections, with the risky `ssh` options (`-o`, `-F`, `-L`/`-R`/`-D` forwarding, `-i`, …) refused, and the server tools only work on their SSH panes |
| Audit / activity retention | 365 / 90 days |
| Public URL | see `ARES_PUBLIC_URL` |

Local shells run **on the server that hosts the app**, as its service account (see `docs/SECURITY.md`).
Keep them for administrators unless every user is trusted with that account.

## Single sign-on
**Admin → Single sign-on** has three independent sections. Any combination can be on at once; the
sign-in page shows a button for Entra ID and for SAML, and LDAP accounts use the normal username and
password form. Accounts from SSO are created on first sign-in when **auto-provision** is on (with the
default role), or must be added by an admin first. Group membership can make someone an administrator
(**admin groups**), limit who may sign in at all (**allowed groups**), and keep the role in step with
the directory at every sign-in (**sync role**).

### Microsoft Entra ID (OpenID Connect)
1. Entra admin center → **App registrations → New registration**. Name: *ARES Terminal Console*.
   Supported account types: *this organisational directory only*.
2. **Redirect URI**: platform *Web*, `https://ares-terminal-console.nacino.net/auth/oidc/callback`
   (the exact value is shown on the Single sign-on page; add the `pre` one,
   `https://ares-terminal-console-demo.nacino.net/auth/oidc/callback`, to a second registration or the same one).
3. **Certificates & secrets → New client secret**. Copy the *value* (not the ID).
4. **Token configuration → Add groups claim**: *Security groups* (or *Groups assigned to the application*),
   ID token: *Group ID*. Optional: **App roles** if you prefer roles over groups; both are read.
5. In the app: **Admin → Single sign-on → Microsoft Entra ID**: tenant ID (Directory ID), client ID
   (Application ID), client secret, username claim (`preferred_username` by default; `email` or `upn`
   also work), admin groups and allowed groups as **group object IDs**. **Test** checks the discovery
   document and the signing keys. Save, enable.
6. Sign in from a private window with **Sign in with Microsoft**.

Users in more than 200 groups get a "group overage" claim instead of the list; use *Groups assigned to
the application* in step 4 so only the groups that matter are sent. Any other OpenID Connect provider
works too: choose *Generic* and give its discovery URL.

### SAML 2.0 (Entra ID, AD FS, Okta, Keycloak, Shibboleth…)
1. Service provider values (shown on the page): entity ID and metadata
   `https://<host>/saml/metadata`, Assertion Consumer Service (POST) `https://<host>/saml/acs`,
   sign-on URL `https://<host>/saml/login`.
2. At the identity provider create a SAML application with those values. Name ID: persistent or email.
   Send the attributes for email, display name and groups.
3. In the app: **Admin → Single sign-on → SAML** → paste the IdP's **federation metadata URL** (or its
   XML) and **Load**: entity ID, sign-on URL and signing certificate(s) are filled in. Choose the username
   (UPN, email or Name ID), groups, then save and enable.

Assertions must be signed (the response, the assertion or both); unsigned or encrypted assertions,
wrong audience, wrong recipient, expired or replayed assertions are refused and audited.

### LDAP / Active Directory
1. Prefer **LDAPS** (`ldaps://dc1.example.com:636`) or `ldap://…:389` with **StartTLS**. Several servers,
   separated by spaces, are tried in order. Certificates are verified; paste the CA certificate if the
   directory uses a private CA.
2. **Bind DN** and password of a read-only service account (stored encrypted), and the **base DN** to
   search, for example `DC=example,DC=com`.
3. **User filter**, `{username}` is replaced (escaped) with what the user typed. The default matches
   `sAMAccountName`, `uid` or `userPrincipalName`. Attributes for username, email, display name and
   groups (`memberOf`).
4. Admin groups and allowed groups as **group DNs** (`CN=Terminal Admins,OU=Groups,DC=example,DC=com`).
5. **Test** with the service account alone, then with a user's username and password; save and enable.

An LDAP user signs in on the normal form with their directory password, then with this app's 2FA code
when the policy requires it. Local accounts are checked first, so `aresadmin` always works, even when
the directory is down.

## Data and backups
State lives only under `DATA_DIR` (`/app/data` in containers, the PVC `ares-terminal-console-data` in
`prod`, `data/` beside the code on `pre`). Backups (local, SFTP, S3), their schedule, the passphrase and
the disaster-recovery runbook: `docs/BACKUP.md`.

## API tokens
Users create their own under **Account → API tokens**; admins see and revoke every token under
**Admin → API tokens**. See `docs/API.md`.

## Audit, activity and logs
**Admin → Audit & Activity**: filters (time, user, action, outcome, path) and CSV / JSON export.
**Admin → Log forwarding**: syslog and HTTPS destinations for a SIEM. See `docs/LOGGING.md`.

## Health and logs
- Health: `GET /healthz` (no sign-in; it does not depend on backups or SSO).
- APEX Pingmora: `GET /healthz/pingmora` (`suite-health/1`, see `docs/API.md`).
- `pre`: `pm2 logs ares-terminal-console` on the app server.
- `prod`: `suite kubectl prod -n ares logs deploy/ares-terminal-console-api` (and `deploy/ares-terminal-console-web`).
