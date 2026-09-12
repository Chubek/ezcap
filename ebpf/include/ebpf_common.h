#pragma once

#include "ebpf_events.h"

typedef struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, EZCAP_RINGBUF_PAGES * 4096);
} ebpf_events_ringbuf_map_t;

extern ebpf_events_ringbuf_map_t events;
