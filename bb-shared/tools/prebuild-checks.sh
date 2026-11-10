#!/usr/bin/env bash
#
# prebuild-checks.sh - what a Cascades project must pass before build-bar.sh compiles it: the mistakes no compiler
# sees, because QML finds its names only when a line runs.
#
#   qml-context-calls-check.js   QML calling into C++ by a name the C++ does not have (Telega 428: video messages
#                                dead for a month after a C++ rename nobody caught)
#   qml-live-text-check.js       a binding that reads a TextField's text - it does not follow typing (KB 1.18)
#
# Usage: prebuild-checks.sh <project dir>     every check runs; exit 1 when any of them fails
#
# A project with no assets/ (a headless service) has nothing for them and passes. A new check goes here, once, and
# every project build-bar.sh builds gets it.

set -uo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${1:-.}"

if ! command -v node >/dev/null 2>&1; then
    echo "error: node not found - the checks need Node.js on the PATH" >&2
    exit 1
fi
if [ ! -d "$PROJECT_DIR/assets" ]; then
    echo "== checks: no assets/ in $PROJECT_DIR - nothing to check"
    exit 0
fi

FAILED=0

echo "== check: every name QML reaches in C++ is there"
if ! node "$TOOLS_DIR/qml-context-calls-check.js" "$PROJECT_DIR"; then
    FAILED=1
fi

echo "== check: no binding reads a TextField's text"
# In batches: a big project's QML would not fit one Windows command line.
if ! find "$PROJECT_DIR/assets" -name '*.qml' -print0 | xargs -0 -n 100 node "$TOOLS_DIR/qml-live-text-check.js"; then
    FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
    echo "== checks: FAILED (see above)"
    exit 1
fi
echo "== checks: all passed"
exit 0
