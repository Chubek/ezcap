#!/usr/bin/env bash
# Format all C/C++ sources with clang-format. With --check, only report.
#
# Usage: scripts/format.sh [--check]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="fix"
[ "${1:-}" = "--check" ] && MODE="check"

CLANG_FORMAT="${CLANG_FORMAT:-clang-format}"
command -v "${CLANG_FORMAT}" >/dev/null 2>&1 || {
  echo "format: clang-format not found (set CLANG_FORMAT=)" >&2
  exit 1
}

FILES=$(find "${REPO_ROOT}"/{include,src,native_host,tests} \
  \( -name '*.cpp' -o -name '*.hpp' -o -name '*.h' \) \
  -not -path '*/generated/*' -not -path '*/third_party/*' 2>/dev/null || true)
# ebpf headers are kernel-world C; include them too, sources use clang anyway.
FILES="${FILES} $(find "${REPO_ROOT}/ebpf/include" -name '*.h' 2>/dev/null || true)"

if [ -z "${FILES// }" ]; then
  echo "format: no sources found" >&2
  exit 1
fi

if [ "${MODE}" = "check" ]; then
  # shellcheck disable=SC2086
  "${CLANG_FORMAT}" --dry-run --Werror ${FILES}
  echo "format: all files conform"
else
  # shellcheck disable=SC2086
  "${CLANG_FORMAT}" -i ${FILES}
  echo "format: done"
fi
