#!/usr/bin/env bash
# Run the detection-engine tests with Node if installed, otherwise with the
# JavaScriptCore shell that ships with macOS.
set -euo pipefail
cd "$(dirname "$0")/.."

JSC=/System/Library/Frameworks/JavaScriptCore.framework/Versions/Current/Helpers/jsc
if command -v node >/dev/null 2>&1; then
  exec node tests/run-tests.js
elif [ -x "$JSC" ]; then
  exec "$JSC" tests/run-tests.js
else
  echo "Need Node.js or macOS JavaScriptCore to run the tests." >&2
  exit 1
fi
