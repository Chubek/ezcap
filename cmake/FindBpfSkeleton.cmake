# Find module for the BPF skeleton toolchain pieces the eBPF build needs.
#
# The eBPF programs are compiled by a script (scripts/build-ebpf.sh) that
# generates vmlinux.h and compiles the .bpf.c sources with clang. This
# module only verifies the toolchain pieces and reports them; it does not
# compile anything itself. When a piece is missing, the eBPF build is
# disabled and the daemon runs on the pcap backend (honest degradation).

include(FindPackageHandleStandardArgs)

find_program(BPFTOOL_EXECUTABLE
  NAMES bpftool
  DOC "bpftool binary used to generate vmlinux.h")

find_program(BPF_CLANG_EXECUTABLE
  NAMES clang
  DOC "clang capable of targeting BPF")

find_program(BPF_LLVM_STRIP_EXECUTABLE
  NAMES llvm-strip
  DOC "llvm-strip used to strip BPF objects")

find_file(BPF_VMLINUX_BTF
  NAMES vmlinux
  HINTS /sys/kernel/btf
  DOC "Kernel BTF blob (required for CO-RE)")

if(BPF_CLANG_EXECUTABLE)
  execute_process(
    COMMAND ${BPF_CLANG_EXECUTABLE} --print-targets
    OUTPUT_VARIABLE _bpf_clang_targets
    ERROR_QUIET
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  if(NOT _bpf_clang_targets MATCHES "bpf")
    set(BPF_CLANG_EXECUTABLE "BPF_CLANG_EXECUTABLE-NOTFOUND" CACHE FILEPATH "" FORCE)
  endif()
endif()

find_package_handle_standard_args(BpfSkeleton
  REQUIRED_VARS BPFTOOL_EXECUTABLE
                BPF_CLANG_EXECUTABLE
                BPF_LLVM_STRIP_EXECUTABLE
                BPF_VMLINUX_BTF)

mark_as_advanced(BPFTOOL_EXECUTABLE BPF_CLANG_EXECUTABLE
  BPF_LLVM_STRIP_EXECUTABLE BPF_VMLINUX_BTF)
