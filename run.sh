#!/bin/sh
# Run ARES Terminal Console on its own, outside ApexBuild.
#
# Identical in shape across every app in the suite: this script starts the app
# and opens a browser, and everything it can do is a flag it passes straight
# through to the launcher.
#
#   ./run.sh                    default host and port
#   ./run.sh --port 9001        somewhere else
#   ./run.sh --no-open          do not open a browser
cd "$(dirname "$0")" || exit 1
exec python3 apexmod run "$@"
