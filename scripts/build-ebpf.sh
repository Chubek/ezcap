#!/usr/bin/env bash
# Compile the ezcap eBPF programs standalone (outside CMake).
#
# Mirrors what ebpf/CMakeLists.txt does: generate vmlinux.h from the
# kernel BTF blob, compile each .bpf.c with clang for the BPF target,
# compile them into one loadable CO-RE object.
#
# Usage: scripts/build-ebpf.sh [output-dir]   (default: ebpf/build)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-${REPO_ROOT}/ebpf/build}"
BTF_FILE="${BTF_FILE:-/sys/kernel/btf/vmlinux}"

BPFTOOL="${BPFTOOL:-bpftool}"
CLANG="${CLANG:-clang}"

ARCH="$(uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/;s/ppc64le/powerpc/;s/mips64el/mips/')"

die() { echo "build-ebpf: $*" >&2; exit 1; }

command -v "${BPFTOOL}" >/dev/null 2>&1 || die "bpftool not found (set BPFTOOL=)"
command -v "${CLANG}" >/dev/null 2>&1 || die "clang not found (set CLANG=)"
[ -f "${BTF_FILE}" ] || die "kernel BTF not found at ${BTF_FILE} (set BTF_FILE=)"

"${CLANG}" --print-targets | grep -q bpf || die "clang lacks the BPF target"

mkdir -p "${OUT_DIR}"

echo "==> generating vmlinux.h from ${BTF_FILE}"
"${BPFTOOL}" btf dump file "${BTF_FILE}" format c > "${OUT_DIR}/vmlinux.h"

CFLAGS=(
  -O2 -g -Wall -Werror -Wno-missing-declarations
  -target bpf
  -D__TARGET_ARCH_"${ARCH}"
  -I"${OUT_DIR}"
  -I"${REPO_ROOT}/ebpf/include"
  -include "${REPO_ROOT}/ebpf/include/ebpf_compat.h"
)

echo "==> compiling CO-RE eBPF programs"
"${CLANG}" "${CFLAGS[@]}" -c "${REPO_ROOT}/ebpf/src/ezcap.bpf.c" \
  -o "${OUT_DIR}/ezcap.bpf.o"

echo "==> done: ${OUT_DIR}/ezcap.bpf.o"
echo "    install to the daemon's fixed load path (EZCAP_EBPF_OBJECT_PATH)"
