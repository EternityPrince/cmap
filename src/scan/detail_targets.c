#include "cmaper/scan/detail_targets.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "cmaper/scan/internal/detail_targets_internal.h"

void cmaper_scan_detail_target_diag_setf(cmaper_scan_detail_target_diag_t *diag,
                                         const char *field, const char *fmt,
                                         ...) {
  va_list args;

  cmaper_scan_detail_target_diag_clear(diag);
  if (diag == NULL) {
    return;
  }

  diag->field = field;
  if (fmt == NULL) {
    return;
  }

  va_start(args, fmt);
  vsnprintf(diag->message, sizeof(diag->message), fmt, args);
  va_end(args);
}

void cmaper_scan_detail_target_dispose(cmaper_scan_detail_target_t *target) {
  if (target == NULL) {
    return;
  }

  if (target->open_tcp_ports != NULL) {
    free(target->open_tcp_ports);
    target->open_tcp_ports = NULL;
  }
  target->open_tcp_port_count = 0;
  target->has_open_tcp_ports = false;
  target->ip[0] = '\0';
}

void cmaper_scan_detail_target_diag_clear(
    cmaper_scan_detail_target_diag_t *diag) {
  if (diag == NULL) {
    return;
  }

  diag->field = NULL;
  diag->message[0] = '\0';
}

void cmaper_scan_detail_targets_init(cmaper_scan_detail_target_list_t *list) {
  if (list == NULL) {
    return;
  }

  list->items = NULL;
  list->count = 0;
}

void cmaper_scan_detail_targets_dispose(
    cmaper_scan_detail_target_list_t *list) {
  size_t i;

  if (list == NULL) {
    return;
  }

  if (list->items != NULL) {
    for (i = 0; i < list->count; ++i) {
      cmaper_scan_detail_target_dispose(&list->items[i]);
    }
    free(list->items);
    list->items = NULL;
  }
  list->count = 0;
}
