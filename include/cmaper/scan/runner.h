#ifndef CMAPER_SCAN_RUNNER_H
#define CMAPER_SCAN_RUNNER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "cmaper/core/error.h"
#include "cmaper/runtime/context.h"
#include "cmaper/scan/artifact.h"
#include "cmaper/scan/command.h"
#include "cmaper/scan/detail.h"
#include "cmaper/scan/detail_targets.h"
#include "cmaper/scan/process.h"
#include "cmaper/scan/source_identity.h"

typedef struct {
  const cmaper_scan_plan_t *plan;
  bool save_discovery_xml;
  bool save_host_xml;
  const char *session_id;
  cmaper_scan_process_run_fn process_backend;
} cmaper_scan_request_t;

typedef struct {
  cmaper_scan_source_identity_t source_identity;
  cmaper_scan_discovery_plan_t discovery_plan;
  cmaper_scan_command_t discovery_command;
  char *discovery_xml;
  size_t discovery_xml_size;
  char *process_stderr;
  size_t process_stderr_size;
  bool discovery_xml_saved;
  char discovery_xml_path[CMAPER_SCAN_ARTIFACT_PATH_CAP];
  char session_id[64];
  cmaper_scan_detail_target_list_t detail_targets;
  cmaper_scan_detail_result_t detail_result;
} cmaper_scan_result_t;

void cmaper_scan_request_init(cmaper_scan_request_t *request);
void cmaper_scan_result_init(cmaper_scan_result_t *result);
void cmaper_scan_result_dispose(cmaper_scan_result_t *result);
void cmaper_scan_result_render_summary(FILE *stream,
                                       const cmaper_scan_result_t *result);

cmaper_err_t cmaper_scan_runner_run(cmaper_runtime_t *runtime,
                                    const cmaper_scan_request_t *request,
                                    cmaper_scan_result_t *result);

#endif
