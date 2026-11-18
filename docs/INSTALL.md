# Installing ARES Terminal Console

ARES Terminal Console comes in two editions from one codebase:

- the **desktop app** for Windows, macOS and Linux: your own terminal on your own computer, no sign-in;
- the **web edition**: a shared server you open in a browser, with users, two-factor authentication and
  single sign-on. The ARES Suite runs it at https://ares-terminal-console.nacino.net (`prod`) and
  https://ares-terminal-console-demo.nacino.net (`pre`, demo); you can also run it yourself in Docker.

## Desktop app

Installers are published, signed, to the ARES Repository (app `ares-terminal-console`). Every file has
a SHA-256 checksum in `SHA256SUMS`. Verify it before installing:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

File names: `ares-terminal-console-<version>-<linux|windows|macos>-<arch>.<ext>`, with `<arch>`
`x86_64` or `arm64`.

### Windows 10 / 11
- `…-windows-x86_64-setup.exe`: installs for you alone, no administrator rights needed (or for all users
  if you choose so in the wizard).
- `…-windows-x86_64.msi`: per machine, for silent or managed installs (Intune, GPO, SCCM):
  `msiexec /i ares-terminal-console-<v>-windows-x86_64.msi /qn`
- `…-windows-x86_64.zip`: portable; extract it and run `ares-terminal-console.exe`.

The installers are not code-signed yet: SmartScreen may ask once (**More info → Run anyway**).

### macOS 11 or later (Apple silicon and Intel)
Open `…-macos-arm64.dmg` (Apple silicon) or `…-macos-x86_64.dmg` (Intel) and drag **ARES Terminal
Console** to Applications. The `.zip` holds the same app. Unsigned for now: the first launch is
right-click → **Open**.

### Linux

| Distribution | Package | Install |
|---|---|---|
| Debian 11+, Ubuntu 20.04+, Mint | `.deb` | `sudo apt install ./ares-terminal-console-<v>-linux-x86_64.deb` |
| Red Hat / Rocky / Alma 9+, Fedora | `.rpm` | `sudo dnf install ./ares-terminal-console-<v>-linux-x86_64.rpm` (on RHEL-likes, EPEL provides the optional `xcb-util-*` packages) |
| Arch Linux, CachyOS, Manjaro, EndeavourOS | `.pkg.tar.zst` | `sudo pacman -U ./ares-terminal-console-<v>-linux-x86_64.pkg.tar.zst` |
| Any distribution | `.AppImage` | `chmod +x ares-terminal-console-*.AppImage && ./ares-terminal-console-*.AppImage` |
| Any distribution, no root | `.tar.gz` | extract it and run `./install.sh` (installs into `~/.local`) |

The window is a native Qt window. `ARES_WINDOW=browser` opens it in a Chrome/Chromium app window instead.

### Where your data is
| OS | Folder |
|---|---|
| Linux | `~/.local/share/ares-terminal-console` (or `$XDG_DATA_HOME/ares-terminal-console`) |
| macOS | `~/Library/Application Support/ARES Terminal Console` |
| Windows | `%APPDATA%\ARES Terminal Console` |

`--data-dir <folder>` uses another folder. Back it up from **Administration → Backup & Restore**
(`docs/BACKUP.md`).

### Uninstall
| Installed with | Remove with |
|---|---|
| `-setup.exe` / `.msi` | Settings → Apps → ARES Terminal Console → Uninstall |
| macOS | drag the app from Applications to the Bin |
| `.deb` | `sudo apt remove ares-terminal-console` |
| `.rpm` | `sudo dnf remove ares-terminal-console` |
| `.pkg.tar.zst` | `sudo pacman -R ares-terminal-console` |
| `.AppImage` | delete the file |
| `.tar.gz` | `./install.sh --remove` from the extracted folder |

Uninstalling keeps your data folder; delete it yourself to remove history and settings too.

## Web edition

### Use the ARES Suite's
Open https://ares-terminal-console.nacino.net and sign in with the account an administrator gave you, or
with **Sign in with Microsoft** / your directory password when single sign-on is set up. The first
sign-in asks you to set up two-factor authentication (`docs/USER_GUIDE.md`).

### Run your own, in Docker
```bash
docker run -d --name ares-terminal -p 3222:3222 -v ares-terminal:/app/data \
  docker.cybercontrol.tech/ares/ares-terminal-console:latest
docker exec ares-terminal cat /app/data/initial-admin-password.txt
```
Open http://localhost:3222, sign in as **`aresadmin`** with that one-time password, choose a new one and
enrol 2FA. Set `-e ARES_ADMIN_PASSWORD=…` on the first start to choose it yourself, and
`-e APP_KEY=$(openssl rand -hex 32)` to keep the encryption key outside the volume. Put TLS in front of
it (any reverse proxy that passes WebSockets and sets `X-Forwarded-Proto`) before it leaves a private
network. The shells run inside the container as user `app`: give it the tools and the network it should
have, nothing more.

The suite's own `pre` and `prod` deployments are described in `docs/DEPLOYMENT.md`.

## From source
Python 3.11+.

```bash
./run.sh                       # local mode: no sign-in, loopback only, standard library only
pip install -r requirements.txt
DATA_DIR=./data python3 app/main.py   # web edition on :3222, with sign-in
```
