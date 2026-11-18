#!/usr/bin/env python3
"""ARES Terminal Console, web edition: the server (Docker, pm2, Kubernetes).

    python app/main.py                      serve (PORT, HOST, DATA_DIR; sign-in required)
    python app/main.py backup create|list|restore <file|name>|prune

Settings come from the environment, then from ``.env`` beside the code (pm2 does not load it).
State lives under ``DATA_DIR`` (default ``./data``). The first start creates the administrator
``aresadmin``; its one-time password is written to ``DATA_DIR/initial-admin-password.txt``
(mode 600) unless ARES_ADMIN_PASSWORD is set.

The desktop app, ``./run.sh`` and ApexBuild use the same server with no sign-in (app/desktop.py,
apexmod); this entry point is only for the multi-user web edition.
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def load_dotenv(path: Path) -> None:
    """KEY=VALUE lines into os.environ; what is already set wins. No interpolation."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:]
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        if k and k not in os.environ:
            os.environ[k] = v


def main(argv: list) -> int:
    load_dotenv(ROOT / ".env")
    os.environ.setdefault("DATA_DIR", str(ROOT / "data"))
    os.environ.setdefault("LOG_FORMAT", "json")
    os.environ.setdefault("ARES_AUTH", "users")
    if argv[:1] == ["backup"]:
        from app.web import backup
        return backup.cli(argv[1:])
    if argv[:1] in (["-h"], ["--help"]):
        print(__doc__)
        return 0
    try:
        port = int(os.environ.get("PORT") or 3222)
    except ValueError:
        print("PORT must be a number", file=sys.stderr)
        return 2
    from app import server
    return server.serve(host=os.environ.get("HOST") or "0.0.0.0", port=port,
                        data_dir=os.environ["DATA_DIR"], auth=os.environ["ARES_AUTH"])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
