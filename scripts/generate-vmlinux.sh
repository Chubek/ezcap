#!/usr/bin/env bash
# Generate vmlinux.h from the running kernel's BTF.
#
# Usage: scripts/generate-vmlinux.sh [output]   (default: ebpf/generated/vmlinux.h)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-${REPO_ROOT}/ebpf/generated/vmlinux.h}"
BTF_FILE="${BTF_FILE:-/sys/kernel/btf/vmlinux}"
BPFTOOL="${BPFTOOL:-bpftool}"

die() { echo "generate-vmlinux: $*" >&2; exit 1; }

command -v "${BPFTOOL}" >/dev/null 2>&1 || die "bpftool not found (set BPFTOOL=)"
[ -f "${BTF_FILE}" ] || die "kernel BTF not found at ${BTF_FILE} (set BTF_FILE=)"

mkdir -p "$(dirname "${OUT}")"
"${BPFTOOL}" btf dump file "${BTF_FILE}" format c > "${OUT}"
echo "wrote ${OUT}"
