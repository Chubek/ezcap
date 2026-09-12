# ezcap CMake options and eBPF capability detection.

option(EZCAP_WITH_EBPF "Build eBPF capture programs (requires clang + kernel BTF)" ON)
option(EZCAP_BUILD_TESTS "Build the test suite" ON)
option(EZCAP_ENABLE_LTO "Enable link-time optimization in release builds" OFF)

set(EZCAP_EXTENSION_ID_CHROMIUM "" CACHE STRING
  "Chromium extension id permitted to connect to the native host")
set(EZCAP_EXTENSION_ID_FIREFOX "" CACHE STRING
  "Firefox extension id permitted to connect to the native host")

# Fixed eBPF object load path (compile-time; never user-configurable).
if(NOT EZCAP_EBPF_OBJECT_PATH)
  set(EZCAP_EBPF_OBJECT_PATH "${CMAKE_INSTALL_FULL_LIBDIR}/ezcap/ezcap.bpf.o"
      CACHE PATH "Fixed path the daemon loads the eBPF object from" FORCE)
endif()

# LTO in release builds.
if(EZCAP_ENABLE_LTO AND NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
  include(CheckIPOSupported)
  check_ipo_supported(RESULT _ezcap_ipo OUTPUT _ezcap_ipo_reason)
  if(_ezcap_ipo)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
  else()
    message(WARNING "IPO requested but unsupported: ${_ezcap_ipo_reason}")
  endif()
endif()

# ---------------------------------------------------------------------------
# eBPF toolchain detection (honest: unsupported stays unsupported)
# ---------------------------------------------------------------------------
if(EZCAP_WITH_EBPF)
  # vmlinux.h needs the BTF blob.
  if(EXISTS "/sys/kernel/btf/vmlinux")
    set(EZCAP_KERNEL_BTF_FOUND TRUE)
  else()
    set(EZCAP_KERNEL_BTF_FOUND FALSE)
    message(STATUS "ezcap: /sys/kernel/btf/vmlinux missing; eBPF build disabled")
  endif()

  find_program(EZCAP_CLANG clang)
  find_program(EZCAP_LLVM_STRIP llvm-strip)
  find_program(EZCAP_BPFTOOL bpftool)

  if(EZCAP_CLANG)
    execute_process(
      COMMAND ${EZCAP_CLANG} --print-targets
      OUTPUT_VARIABLE _clang_targets
      ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(_clang_targets MATCHES "bpf")
      set(EZCAP_CLANG_BPF_TARGET TRUE)
    else()
      set(EZCAP_CLANG_BPF_TARGET FALSE)
      message(STATUS "ezcap: clang lacks the BPF target; eBPF build disabled")
    endif()
  else()
    set(EZCAP_CLANG_BPF_TARGET FALSE)
    message(STATUS "ezcap: clang not found; eBPF build disabled")
  endif()

  # bpftool is needed to generate vmlinux.h; without it we cannot build
  # CO-RE programs. (DWARF-based headers are not attempted — honest
  # degradation to the pcap backend instead.)
  if(EZCAP_BPFTOOL AND EZCAP_KERNEL_BTF_FOUND AND EZCAP_CLANG_BPF_TARGET)
    set(EZCAP_EBPF_SUPPORTED TRUE)
    message(STATUS "ezcap: eBPF build enabled (clang: ${EZCAP_CLANG}, bpftool: ${EZCAP_BPFTOOL})")
  else()
    set(EZCAP_EBPF_SUPPORTED FALSE)
    if(NOT EZCAP_BPFTOOL)
      message(STATUS "ezcap: bpftool not found; eBPF build disabled "
                     "(the daemon will fall back to pcap)")
    endif()
  endif()
else()
  set(EZCAP_EBPF_SUPPORTED FALSE)
endif()
