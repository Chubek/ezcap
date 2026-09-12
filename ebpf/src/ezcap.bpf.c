/* Keep all programs in one CO-RE translation unit. GNU ld partial linking
 * corrupts BTF.ext relocation metadata and yields objects libbpf cannot load. */
#include "connect.bpf.c"
#include "dns.bpf.c"
#include "socket_state.bpf.c"
