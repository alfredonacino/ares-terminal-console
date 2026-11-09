#!/bin/sh
# Build, check and push the ARES Terminal Console image.
#
#   packaging/docker/docker-push.sh                 # VERSION and latest to $REGISTRY
#   REGISTRY=other.example packaging/docker/docker-push.sh
#   packaging/docker/docker-push.sh --no-push       # build and check only
#
# The check runs the image, waits for its health endpoint, confirms the token
# gate refuses a request without it, and opens a shell through the API.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
REGISTRY="${REGISTRY:-docker.cybercontrol.tech}"
IMAGE="$REGISTRY/ares/terminal-console"
VERSION=$(sed -n 's/^version *= *"\(.*\)".*/\1/p' "$ROOT/apexmodule.toml")
PUSH=1; [ "${1:-}" = "--no-push" ] && PUSH=0

echo "==> building $IMAGE:$VERSION"
docker build -q --build-arg VERSION="$VERSION" -t "$IMAGE:$VERSION" -t "$IMAGE:latest" "$ROOT"

echo "==> checking the image"
NAME="ares-terminal-check-$$"
docker run -d --rm --name "$NAME" -e ARES_ACCESS_TOKEN=check-token-0123456789abcdef "$IMAGE:$VERSION" >/dev/null
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
docker exec -i "$NAME" python - <<'PY'
import json, time, urllib.request, urllib.error
base = "http://127.0.0.1:8080"
for _ in range(50):
    try:
        h = json.load(urllib.request.urlopen(base + "/api/health", timeout=2)); break
    except OSError:
        time.sleep(0.2)
else:
    raise SystemExit("FAIL  the health endpoint never answered")
checks = [("health answers " + h["app"] + " " + h["version"], h["ok"]), ("a pty is available", h["supported"])]
try:
    urllib.request.urlopen(base + "/api/sessions", timeout=5); refused = False
except urllib.error.HTTPError as e:
    refused = e.code == 401
checks.append(("the API refuses a request without the token", refused))
cookie = {"Cookie": "ares_terminal_console=check-token-0123456789abcdef", "Content-Type": "application/json"}
req = urllib.request.Request(base + "/api/sessions", method="POST", headers=cookie,
                             data=json.dumps({"command": "/bin/sh -c 'echo ok'"}).encode())
s = json.load(urllib.request.urlopen(req, timeout=10))
checks.append(("a shell opens with the token", s.get("ok") is True))
for name, ok in checks:
    print(("PASS  " if ok else "FAIL  ") + name)
print(f"{sum(ok for _, ok in checks)}/{len(checks)} checks passed")
raise SystemExit(0 if all(ok for _, ok in checks) else 1)
PY

if [ "$PUSH" = 1 ]; then
  echo "==> pushing"
  docker push -q "$IMAGE:$VERSION"
  docker push -q "$IMAGE:latest"
  echo "digest: $(docker inspect --format '{{index .RepoDigests 0}}' "$IMAGE:$VERSION")"
fi
