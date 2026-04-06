#ifndef CMAPER_SCAN_HEARTBEAT_H
#define CMAPER_SCAN_HEARTBEAT_H

#include <stdbool.h>

typedef struct {
    int interval_seconds;
    long long started_ms;
    long long next_tick_ms;
} cmaper_scan_heartbeat_t;

long long cmaper_scan_now_ms(void);

void cmaper_scan_heartbeat_init(
    cmaper_scan_heartbeat_t *heartbeat,
    int interval_seconds,
    long long now_ms
);

bool cmaper_scan_heartbeat_should_emit(
    cmaper_scan_heartbeat_t *heartbeat,
    long long now_ms,
    long long *elapsed_ms
);

#endif
