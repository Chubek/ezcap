if(NOT EXISTS "${BPFTOOL_EXECUTABLE}")
  message(FATAL_ERROR "Cannot locate bpftool executable: ${BPFTOOL_EXECUTABLE}")
endif()

if(NOT EXISTS "${BTF_SOURCE}")
  message(FATAL_ERROR "Cannot read BTF source: ${BTF_SOURCE}")
endif()

if(OUTPUT_H STREQUAL "")
  message(FATAL_ERROR "OUTPUT_H must be provided for generated vmlinux.h")
endif()

execute_process(
  COMMAND "${BPFTOOL_EXECUTABLE}" btf dump file "${BTF_SOURCE}" format c
  OUTPUT_FILE "${OUTPUT_H}"
  ERROR_VARIABLE _vmlinux_btf_err
  RESULT_VARIABLE _vmlinux_btf_rc
)

if(NOT _vmlinux_btf_rc EQUAL 0)
  message(FATAL_ERROR
    "bpftool btf dump failed with ${_vmlinux_btf_rc}: ${_vmlinux_btf_err}")
endif()
