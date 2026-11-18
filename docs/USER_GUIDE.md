# ARES Terminal Console - User guide

Split-pane terminals in a window or a browser tab: open shells and SSH connections side by side, type
into all of them at once, and come back to sessions that kept running while you were away. The full
feature tour is in the README; this page is task by task.

## Signing in (web edition)
The desktop app opens straight into the terminal: there is nothing to sign in to. In the browser:

1. Open https://ares-terminal-console.nacino.net.
2. Sign in one of three ways, whichever your administrator set up:
   - **Sign in with Microsoft** (Entra ID) or your organisation's SSO button;
   - your **directory (LDAP / Active Directory)** username and password, on the normal form;
   - a **local account** an administrator created for you.
3. First time with a local account: choose a new password (12+ characters, three of lowercase,
   uppercase, digits, symbols; not your username).
4. **Two-factor authentication.** If you have not set it up yet you are asked to now: scan the QR code
   with an authenticator app (Microsoft Authenticator, Google Authenticator, 1Password, Bitwarden…),
   type the 6-digit code it shows, and **save the 10 recovery codes** somewhere safe. Each works once if
   you lose your phone. From then on, sign-in asks for the current code.

Too many wrong passwords lock the account for a while (15 minutes by default). Lost both your phone and
the recovery codes: ask an administrator to **reset your 2FA**.

## Your account
Click your name in the top bar → **Account**:
- **Password**: change it (local accounts; SSO and LDAP passwords are changed in your directory).
- **Two-factor authentication**: see when it was set up, make new recovery codes, or turn it off if the
  policy allows.
- **API tokens**: for scripts (`docs/API.md`). A token is shown once; copy it then.
- **Sign out**. Signing out does not stop your terminals: they keep running and are there when you
  sign in again, until the server restarts.

## Main tasks
| Task | How |
|---|---|
| Open a terminal | **+ Pane**, or `Ctrl+Shift+Enter` |
| Connect to a server | **⇄ connect…** (`user@host`, port), or type `ssh user@host` in a pane. It opens in a tab of its own |
| Split | `Ctrl+Shift+D` beside, `Ctrl+Shift+E` below; drag a divider to resize |
| Tabs | **+** new tab with a local shell, `Ctrl+Shift+T`; `Ctrl+PageUp` / `PageDown` to move; double-click to rename |
| Type into every pane at once | **Broadcast** (`Ctrl+Shift+S`); the bar turns amber while it is on. **send to all** sends one line once |
| Keep an idle connection alive | **Anti-idle**: 30 s to 5 min |
| Come back to a session | close the tab, lose the network, come back: the pane replays its scrollback and carries on. **Running** in the drawer lists sessions no pane is showing |
| Find a command you ran | **⌘** on a pane, or **Commands** in the drawer (`Ctrl+Shift+L`); **Insert** puts it back on the prompt unsent |
| Reconnect to a server | **Servers** in the drawer (`Ctrl+Shift+H`): every SSH destination you used, with **Connect** |
| Look at a server | the card in the top-right corner of the focused pane (`Ctrl+Shift+X`): health, performance, logs, AI log analysis, packages, vulnerability scan, history. Read-only |
| Ask how to do something | the **ask** bar (`Ctrl+Shift+A`, desktop app): proposes a command, never runs it |

In the web edition your terminals, history and servers are yours alone: other users do not see them, and
you do not see theirs. Depending on your organisation's policy you may only be allowed **SSH connections**
(no shell on the web server itself); the **+ Pane** button then asks for a server.

## Settings
Everything you change in the window (layout, tabs, the folded server card, anti-idle) is remembered in
this browser or desktop app. Saved connections and history are kept on the server for your account (web)
or in your data folder (desktop).

## Troubleshooting
| Symptom | What to do |
|---|---|
| "Your session has ended" | You were idle longer than the policy allows, or an administrator signed you out. Sign in again; your terminals are still running |
| The 2FA code is refused | Check the time on your phone is set automatically; codes change every 30 seconds. Use a recovery code if needed |
| "Sign in with Microsoft" says you are not allowed | You are not in a group allowed to use the app: ask your administrator |
| A pane says it cannot open a shell on this server | The policy limits you to SSH connections: use **⇄ connect…** |
| SSH asks for the host key | First connection to that server from your account: compare the fingerprint, then answer `yes` |
| The terminal froze after the laptop slept | It reconnects by itself; if not, reload the page. The session kept running |
| The desktop app does not start on Linux | Install the packages listed for your distribution in `docs/INSTALL.md`, or try `ARES_WINDOW=browser` |
