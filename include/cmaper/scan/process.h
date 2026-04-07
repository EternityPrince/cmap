#ifndef CMAPER_SCAN_PROCESS_H
#define CMAPER_SCAN_PROCESS_H

#include <stdbool.h>
#include <stddef.h>

#include "cmaper/core/error.h"
#include "cmaper/core/log.h"

#define CMAPER_SCAN_PROCESS_CAPTURE_LIMIT (16U * 1024U * 1024U)

typedef struct {
  const char *program_path;
  const char *const *argv;
  int heartbeat_seconds;
  const char *heartbeat_label;
  int hard_timeout_seconds;
} cmaper_scan_process_request_t;

typedef struct {
  int exit_code;
  bool exited_by_signal;
  int signal_number;
  char *stdout_data;
  size_t stdout_size;
  char *stderr_data;
  size_t stderr_size;
} cmaper_scan_process_result_t;

typedef cmaper_err_t (*cmaper_scan_process_run_fn)(
    const cmaper_scan_process_request_t *request, cmaper_logger_t *logger,
    cmaper_scan_process_result_t *result);

void cmaper_scan_process_result_init(cmaper_scan_process_result_t *result);
void cmaper_scan_process_result_dispose(cmaper_scan_process_result_t *result);

cmaper_err_t
cmaper_scan_process_run(const cmaper_scan_process_request_t *request,
                        cmaper_logger_t *logger,
                        cmaper_scan_process_result_t *result);

#endif
