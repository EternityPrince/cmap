#ifndef CMAPER_PREFLIGHT_CHECK_H
#define CMAPER_PREFLIGHT_CHECK_H

#include <stdbool.h>
#include <stdio.h>

#include "cmaper/core/error.h"
#include "cmaper/core/log.h"
#include "cmaper/runtime/paths.h"

typedef struct {
  bool nmap_found;
  bool db_dir_ready;
  bool xml_output_dir_ready;
  bool scripts_dir_ready;
  bool helper_selftest_ok;
  bool stdout_available;
  bool stderr_available;
  bool stdout_stderr_separated;
  bool success;
} cmaper_preflight_report_t;

void cmaper_preflight_report_init(cmaper_preflight_report_t *report);

cmaper_err_t cmaper_preflight_run(const cmaper_runtime_paths_t *paths,
                                  cmaper_logger_t *logger,
                                  cmaper_preflight_report_t *report);

void cmaper_preflight_render_report(FILE *stream,
                                    const cmaper_preflight_report_t *report,
                                    const cmaper_runtime_paths_t *paths);

#endif
