#!/usr/bin/env bash
# Compile the ezcap eBPF programs standalone (outside CMake).
#
# Mirrors what ebpf/CMakeLists.txt does: generate vmlinux.h from the
# kernel BTF blob, compile each .bpf.c with clang for the BPF target,
# strip, and partial-link them into a single loadable object.
#
# Usage: scripts/build-ebpf.sh [output-dir]   (default: ebpf/build)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-${REPO_ROOT}/ebpf/build}"
BTF_FILE="${BTF_FILE:-/sys/kernel/btf/vmlinux}"

BPFTOOL="${BPFTOOL:-bpftool}"
CLANG="${CLANG:-clang}"
LLVM_STRIP="${LLVM_STRIP:-llvm-strip}"
LD="${LD:-ld}"

ARCH="$(uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/;s/ppc64le/powerpc/;s/mips64el/mips/')"

die() { echo "build-ebpf: $*" >&2; exit 1; }

command -v "${BPFTOOL}" >/dev/null 2>&1 || die "bpftool not found (set BPFTOOL=)"
command -v "${CLANG}" >/dev/null 2>&1 || die "clang not found (set CLANG=)"
command -v "${LLVM_STRIP}" >/dev/null 2>&1 || die "llvm-strip not found (set LLVM_STRIP=)"
[ -f "${BTF_FILE}" ] || die "kernel BTF not found at ${BTF_FILE} (set BTF_FILE=)"

"${CLANG}" --print-targets | grep -q bpf || die "clang lacks the BPF target"

mkdir -p "${OUT_DIR}"

echo "==> generating vmlinux.h from ${BTF_FILE}"
"${BPFTOOL}" btf dump file "${BTF_FILE}" format c > "${OUT_DIR}/vmlinux.h"

CFLAGS=(
  -O2 -g -Wall -Werror
  -target bpf
  -D__TARGET_ARCH_"${ARCH}"
  -I"${OUT_DIR}"
  -I"${REPO_ROOT}/ebpf/include"
  -include "${REPO_ROOT}/ebpf/include/ebpf_compat.h"
)

OBJS=()
for src in connect dns socket_state; do
  obj="${OUT_DIR}/${src}.bpf.o"
  echo "==> compiling ${src}.bpf.c"
  "${CLANG}" "${CFLAGS[@]}" -c "${REPO_ROOT}/ebpf/src/${src}.bpf.c" -o "${obj}"
  "${LLVM_STRIP}" -g "${obj}"
  OBJS+=("${obj}")
done

echo "==> partial-linking combined object"
"${LD}" -r -m "elf64${ARCH//[0-9]/}bpf" -o "${OUT_DIR}/ezcap.bpf.o" "${OBJS[@]}"

echo "==> done: ${OUT_DIR}/ezcap.bpf.o"
echo "    install to the daemon's fixed load path (EZCAP_EBPF_OBJECT_PATH)"
