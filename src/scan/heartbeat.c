#include "cmaper/scan/heartbeat.h"

#include <time.h>

long long cmaper_scan_now_ms(void) {
  struct timespec ts;

  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }

  return ((long long)ts.tv_sec * 1000LL) + ((long long)ts.tv_nsec / 1000000LL);
}

void cmaper_scan_heartbeat_init(cmaper_scan_heartbeat_t *heartbeat,
                                int interval_seconds, long long now_ms) {
  if (heartbeat == NULL) {
    return;
  }

  heartbeat->interval_seconds = interval_seconds;
  heartbeat->started_ms = now_ms;
  heartbeat->next_tick_ms = now_ms + ((long long)interval_seconds * 1000LL);
}

bool cmaper_scan_heartbeat_should_emit(cmaper_scan_heartbeat_t *heartbeat,
                                       long long now_ms,
                                       long long *elapsed_ms) {
  if (heartbeat == NULL || heartbeat->interval_seconds <= 0) {
    return false;
  }

  if (elapsed_ms != NULL) {
    *elapsed_ms = now_ms - heartbeat->started_ms;
    if (*elapsed_ms < 0) {
      *elapsed_ms = 0;
    }
  }

  if (now_ms < heartbeat->next_tick_ms) {
    return false;
  }

  do {
    heartbeat->next_tick_ms +=
        ((long long)heartbeat->interval_seconds * 1000LL);
  } while (now_ms >= heartbeat->next_tick_ms);

  return true;
}
