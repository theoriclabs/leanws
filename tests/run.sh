#!/usr/bin/env bash
set -euo pipefail

# The loopback suite opens ~2,000 sockets in one process; raise the soft
# descriptor limit when the shell default (often 256 on macOS) is lower.
ulimit -n 8192 2>/dev/null || true

cd "$(dirname "$0")/.."
lake build leanws_tests
./.lake/build/bin/leanws_tests "$@"
