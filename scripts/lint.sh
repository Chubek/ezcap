#!/usr/bin/env bash
# Lint the codebase: clang-tidy over C/C++ (when available), tsc for the
# extension. Exits non-zero on any finding.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATUS=0

# --- C/C++ (clang-tidy) ------------------------------------------------------
if command -v clang-tidy >/dev/null 2>&1 && [ -d "${REPO_ROOT}/build" ]; then
  echo "==> clang-tidy (using build/compile_commands.json)"
  FILES=$(find "${REPO_ROOT}"/{src,native_host,tests} -name '*.cpp' 2>/dev/null || true)
  # shellcheck disable=SC2086
  clang-tidy -p "${REPO_ROOT}/build" -quiet ${FILES} || STATUS=1
else
  echo "==> skipping clang-tidy (needs clang-tidy installed and build/ configured)"
fi

# --- Extension (tsc) ---------------------------------------------------------
if command -v npm >/dev/null 2>&1 && [ -f "${REPO_ROOT}/extension/package.json" ]; then
  echo "==> tsc --noEmit (extension)"
  (cd "${REPO_ROOT}/extension" && npm run --silent check) || STATUS=1
else
  echo "==> skipping extension check (npm missing or no package.json)"
fi

exit "${STATUS}"
