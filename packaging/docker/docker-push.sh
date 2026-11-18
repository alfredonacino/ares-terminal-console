#!/bin/sh
# Build the ARES Terminal Console server image and check it before it is pushed.
#
#   packaging/docker/docker-push.sh            # build + check, then push with the suite tooling
#   packaging/docker/docker-push.sh --no-push  # build + check only
#
# Pushing (server and web images, <version> and latest, OCI labels, registry login) is
# `suite docker push`; this script only adds the smoke test: the image starts, answers
# /healthz, refuses the API without a sign-in, and created the first administrator.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
VERSION=$(cat "$ROOT/VERSION")
IMAGE="ares-terminal-console-check:$VERSION"
PUSH=1; [ "${1:-}" = "--no-push" ] && PUSH=0

echo "==> building $IMAGE"
docker build -q --build-arg APP_VERSION="$VERSION" -t "$IMAGE" "$ROOT" >/dev/null

echo "==> checking the image"
NAME="ares-terminal-check-$$"
docker run -d --rm --name "$NAME" "$IMAGE" >/dev/null
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
docker exec -i "$NAME" python - <<'PY'
import json, os, time, urllib.request, urllib.error
base = "http://127.0.0.1:" + os.environ.get("PORT", "3222")
for _ in range(60):
    try:
        h = json.load(urllib.request.urlopen(base + "/healthz", timeout=2)); break
    except OSError:
        time.sleep(0.5)
else:
    raise SystemExit("FAIL /healthz never answered")
print("PASS /healthz", h)
try:
    urllib.request.urlopen(base + "/api/sessions", timeout=5)
    raise SystemExit("FAIL /api/sessions answered without a sign-in")
except urllib.error.HTTPError as e:
    assert e.code in (401, 403), e.code
    print("PASS /api/sessions refused without a sign-in:", e.code)
assert os.path.exists("/app/data/initial-admin-password.txt"), "no initial admin password file"
print("PASS first administrator created (one-time password file present)")
PY
[ "$PUSH" = 1 ] && (cd "$ROOT" && suite docker push)
echo "==> ok"
