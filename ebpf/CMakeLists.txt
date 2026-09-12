# eBPF build: generate vmlinux.h (when bpftool exists), compile the
# purpose-specific programs, and place the object at the fixed path the
# daemon loads. When the toolchain is incomplete this subdirectory is
# never entered — the daemon degrades to pcap honestly.

set(EZCAP_EBPF_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(EZCAP_EBPF_GEN_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${EZCAP_EBPF_GEN_DIR}")

# vmlinux.h from the kernel BTF blob.
add_custom_command(
  OUTPUT "${EZCAP_EBPF_GEN_DIR}/vmlinux.h"
  COMMAND ${BPFTOOL_EXECUTABLE} btf dump file /sys/kernel/btf/vmlinux
          format c > "${EZCAP_EBPF_GEN_DIR}/vmlinux.h"
  DEPENDS /sys/kernel/btf/vmlinux
  COMMENT "Generating vmlinux.h from kernel BTF"
  VERBATIM)

set(EZCAP_BPF_CFLAGS
  -O2
  -g
  -Wall
  -Werror
  -target bpf
  -D__TARGET_ARCH_${CMAKE_SYSTEM_PROCESSOR}
  -I"${EZCAP_EBPF_GEN_DIR}"
  -I"${EZCAP_EBPF_SRC_DIR}/include"
  -include "${EZCAP_EBPF_SRC_DIR}/include/ebpf_compat.h")

# One object per program source; all are linked into a single loadable
# object by the loader? No — libbpf opens one object file containing all
# programs. Compile them into one relocatable via partial linking.
set(EZCAP_BPF_OBJECTS
  "${EZCAP_EBPF_GEN_DIR}/connect.bpf.o"
  "${EZCAP_EBPF_GEN_DIR}/dns.bpf.o"
  "${EZCAP_EBPF_GEN_DIR}/socket_state.bpf.o")

add_custom_command(
  OUTPUT ${EZCAP_BPF_OBJECTS}
  COMMAND ${BPF_CLANG_EXECUTABLE} ${EZCAP_BPF_CFLAGS}
          -c "${EZCAP_EBPF_SRC_DIR}/src/connect.bpf.c"
          -o "${EZCAP_EBPF_GEN_DIR}/connect.bpf.o"
  COMMAND ${BPF_CLANG_EXECUTABLE} ${EZCAP_BPF_CFLAGS}
          -c "${EZCAP_EBPF_SRC_DIR}/src/dns.bpf.c"
          -o "${EZCAP_EBPF_GEN_DIR}/dns.bpf.o"
  COMMAND ${BPF_CLANG_EXECUTABLE} ${EZCAP_BPF_CFLAGS}
          -c "${EZCAP_EBPF_SRC_DIR}/src/socket_state.bpf.c"
          -o "${EZCAP_EBPF_GEN_DIR}/socket_state.bpf.o"
  DEPENDS "${EZCAP_EBPF_GEN_DIR}/vmlinux.h"
          "${EZCAP_EBPF_SRC_DIR}/src/connect.bpf.c"
          "${EZCAP_EBPF_SRC_DIR}/src/dns.bpf.c"
          "${EZCAP_EBPF_SRC_DIR}/src/socket_state.bpf.c"
  COMMENT "Compiling eBPF programs"
  VERBATIM)

# Note: each .bpf.c is self-contained with its own map definitions, so
# they are installed as separate objects; the daemon's loader opens the
# combined object produced by the linker below.
add_custom_command(
  OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/ezcap.bpf.o"
  COMMAND ${CMAKE_LINKER} -r -m elf64lbpf
          -o "${CMAKE_CURRENT_BINARY_DIR}/ezcap.bpf.o"
          ${EZCAP_BPF_OBJECTS}
  DEPENDS ${EZCAP_BPF_OBJECTS}
  COMMENT "Linking combined eBPF object"
  VERBATIM)

add_custom_target(ezcap_ebpf ALL
  DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/ezcap.bpf.o")

# Copy the combined object to the top-level binary dir so the install()
# rule in the root CMakeLists picks it up.
add_custom_command(
  TARGET ezcap_ebpf POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${CMAKE_CURRENT_BINARY_DIR}/ezcap.bpf.o"
          "${CMAKE_BINARY_DIR}/ezcap.bpf.o"
  VERBATIM)
