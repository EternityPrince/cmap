#include "cmaper/app/app.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "cmaper/app/app_errors.h"
#include "cmaper/cli/config.h"
#include "cmaper/cli/diagnostic.h"
#include "cmaper/cli/help.h"
#include "cmaper/cli/parser.h"
#include "cmaper/cli/raw.h"
#include "cmaper/cli/validate.h"
#include "cmaper/core/error.h"
#include "cmaper/history/service.h"
#include "cmaper/preflight/check.h"
#include "cmaper/runtime/context.h"
#include "cmaper/runtime/paths.h"
#include "cmaper/scan/plan.h"
#include "cmaper/scan/runner.h"
#include "cmaper/snapshot/store.h"

static const char *cmaper_program_name(char *argv0) {
  const char *program_name_env;
  const char *slash;

program_name_env = getenv("CMAPER_PROGRAM_NAME");
  if (program_name_env != NULL && program_name_env[0] != '\0') {
    return program_name_env;
  }

  if (argv0 == NULL || argv0[0] == '\0') {
    return "cmaper";
  }

  slash = strrchr(argv0, '/');
  if (slash != NULL && slash[1] != '\0') {
    return slash + 1;
  }

  return argv0;
}

int app_run(int argc, char **argv) {
  cmaper_cli_raw_args_t raw_args;
  cmaper_cli_config_t config;
  cmaper_cli_diagnostic_t diag;
  cmaper_scan_plan_t scan_plan;
  cmaper_scan_plan_diag_t scan_diag;
  cmaper_scan_request_t scan_request;
  cmaper_scan_result_t scan_result;
  cmaper_runtime_paths_diag_t paths_diag;
  cmaper_preflight_report_t preflight_report;
  cmaper_runtime_t runtime;
  cmaper_snapshot_store_t snapshot_store;
  cmaper_snapshot_diag_t snapshot_diag;
  cmaper_snapshot_session_start_t snapshot_session_start;
  cmaper_snapshot_session_fail_t snapshot_session_fail;
  cmaper_snapshot_session_complete_t snapshot_session_complete;
  cmaper_snapshot_write_request_t snapshot_write_request;
  cmaper_history_service_request_t history_request;
  char session_uid[64];
  cmaper_err_t rc;
  const char *program_name = cmaper_program_name(argc > 0 ? argv[0] : NULL);

  rc = cmaper_cli_parse_raw_argv(&raw_args, argc, argv, &diag);
  if (rc != CMAPER_OK) {
    return cmaper_app_usage_error(program_name, &diag);
  }

  rc = cmaper_cli_normalize_config(&config, &raw_args, &diag);
  if (rc != CMAPER_OK) {
    return cmaper_app_usage_error(program_name, &diag);
  }

  rc = cmaper_cli_validate_config(&config, &diag);
  if (rc != CMAPER_OK) {
    return cmaper_app_usage_error(program_name, &diag);
  }

  if (config.intent == CMAPER_CLI_INTENT_HELP) {
    cmaper_cli_print_help(stdout, program_name, config.help_topic);
    return 0;
  }

  if (config.intent == CMAPER_CLI_INTENT_VERSION) {
    cmaper_cli_print_version(stdout, program_name);
    return 0;
  }

  rc = cmaper_runtime_init(&runtime, &config, &paths_diag);
  if (rc != CMAPER_OK) {
    return cmaper_app_runtime_error(program_name, &paths_diag);
  }

  if (config.mode == CMAPER_CLI_MODE_CHECK || config.dev_mode) {
    rc = cmaper_preflight_run(&runtime.paths, &runtime.logger,
                              &preflight_report);
    if (config.mode == CMAPER_CLI_MODE_CHECK) {
      cmaper_preflight_render_report(stdout, &preflight_report, &runtime.paths);
      cmaper_runtime_dispose(&runtime);
      return cmaper_err_to_exit_code(rc);
    }
    if (rc != CMAPER_OK) {
      cmaper_runtime_dispose(&runtime);
      return cmaper_err_to_exit_code(rc);
    }
  }

  if (config.mode == CMAPER_CLI_MODE_SCAN) {
    rc = cmaper_scan_plan_normalize(&scan_plan, &config.scan, &scan_diag);
    if (rc != CMAPER_OK) {
      cmaper_runtime_dispose(&runtime);
      return cmaper_app_scan_plan_error(program_name, &scan_diag);
    }
  }

  if (config.mode != CMAPER_CLI_MODE_SCAN) {
    history_request.config = &config;
    history_request.paths = &runtime.paths;
    history_request.logger = &runtime.logger;
    history_request.report_stream = stdout;

    rc = cmaper_history_service_run(&history_request);
    cmaper_runtime_dispose(&runtime);
    return cmaper_err_to_exit_code(rc);
  }

  if (config.mode == CMAPER_CLI_MODE_SCAN) {
    bool persistence_enabled = !config.xml_only;

    cmaper_scan_plan_render_summary(stdout, &scan_plan);
    fflush(stdout);

    cmaper_snapshot_store_init(&snapshot_store);
    cmaper_snapshot_diag_clear(&snapshot_diag);
    rc = cmaper_snapshot_store_open(&snapshot_store, &runtime.paths,
                                    persistence_enabled, &runtime.logger,
                                    &snapshot_diag);
    if (rc != CMAPER_OK) {
      cmaper_runtime_dispose(&runtime);
      return cmaper_app_snapshot_error(program_name, &snapshot_diag);
    }

    cmaper_app_make_session_uid(session_uid, sizeof(session_uid));
    snapshot_session_start.session_uid = session_uid;
    snapshot_session_start.plan = &scan_plan;
    rc =
        cmaper_snapshot_session_start(&snapshot_store, &snapshot_session_start);
    if (rc != CMAPER_OK) {
      cmaper_snapshot_store_close(&snapshot_store);
      cmaper_runtime_dispose(&runtime);
      return cmaper_err_to_exit_code(rc);
    }

    cmaper_scan_request_init(&scan_request);
    cmaper_scan_result_init(&scan_result);
    scan_request.plan = &scan_plan;
    scan_request.save_discovery_xml = true;
    scan_request.save_host_xml = true;
    scan_request.session_id = session_uid;

    rc = cmaper_scan_runner_run(&runtime, &scan_request, &scan_result);
    if (rc != CMAPER_OK) {
      snapshot_session_fail.session_uid = session_uid;
      snapshot_session_fail.error_message = "scan runner failed";
      (void)cmaper_snapshot_session_fail(&snapshot_store,
                                         &snapshot_session_fail);
      cmaper_scan_result_dispose(&scan_result);
      cmaper_snapshot_store_close(&snapshot_store);
      cmaper_runtime_dispose(&runtime);
      return cmaper_err_to_exit_code(rc);
    }

    snapshot_write_request.session_uid = session_uid;
    snapshot_write_request.plan = &scan_plan;
    snapshot_write_request.scan_result = &scan_result;
    rc = cmaper_snapshot_store_write_scan(
        &snapshot_store, &snapshot_write_request, &runtime.logger);
    if (rc != CMAPER_OK) {
      snapshot_session_fail.session_uid = session_uid;
      snapshot_session_fail.error_message = "snapshot write failed";
      (void)cmaper_snapshot_session_fail(&snapshot_store,
                                         &snapshot_session_fail);
      cmaper_scan_result_dispose(&scan_result);
      cmaper_snapshot_store_close(&snapshot_store);
      cmaper_runtime_dispose(&runtime);
      return cmaper_err_to_exit_code(rc);
    }

    snapshot_session_complete.session_uid = session_uid;
    snapshot_session_complete.discovery_xml_path =
        scan_result.discovery_xml_path;
    snapshot_session_complete.detail_targets_total =
        scan_result.detail_targets.count;
    snapshot_session_complete.detail_hosts_success =
        scan_result.detail_result.successful_hosts;
    snapshot_session_complete.detail_hosts_failed =
        scan_result.detail_result.failed_hosts;
    snapshot_session_complete.detail_hosts_degraded =
        scan_result.detail_result.degraded_hosts;
    rc = cmaper_snapshot_session_complete(&snapshot_store,
                                          &snapshot_session_complete);
    if (rc != CMAPER_OK) {
      snapshot_session_fail.session_uid = session_uid;
      snapshot_session_fail.error_message = "snapshot session finalize failed";
      (void)cmaper_snapshot_session_fail(&snapshot_store,
                                         &snapshot_session_fail);
      cmaper_scan_result_dispose(&scan_result);
      cmaper_snapshot_store_close(&snapshot_store);
      cmaper_runtime_dispose(&runtime);
      return cmaper_err_to_exit_code(rc);
    }

    cmaper_scan_result_render_summary(stdout, &scan_result);
    fflush(stdout);
    cmaper_scan_result_dispose(&scan_result);
    cmaper_snapshot_store_close(&snapshot_store);
    cmaper_runtime_dispose(&runtime);
    return 0;
  }

  cmaper_runtime_dispose(&runtime);
  return cmaper_err_to_exit_code(CMAPER_ERR_INTERNAL);
}
