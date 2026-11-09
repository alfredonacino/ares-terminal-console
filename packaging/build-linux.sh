#!/bin/sh
# Build the Linux packages inside Debian 11 (glibc 2.31) so they run on Ubuntu 20.04+, Debian 11+,
# RHEL 9+ and newer. Output: dist/*.tar.gz, dist/*.deb
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
docker build -q -t ares-terminal-console-builder -f "$ROOT/packaging/linux/Dockerfile.build" "$ROOT/packaging/linux" >/dev/null
docker run --rm -v "$ROOT":/src -w /src -e HOME=/tmp -e PIP_CACHE_DIR=/src/build/pip-cache -e PIP_RETRIES=10 -e PIP_DEFAULT_TIMEOUT=60 -u "$(id -u):$(id -g)" ares-terminal-console-builder \
  sh -c 'python packaging/build.py "$@"' build "$@"
