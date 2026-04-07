#include "cmaper/scan/internal/detail_internal.h"

#include <stdio.h>
#include <string.h>

#include "cmaper/platform/fs.h"
#include "cmaper/scan/command.h"

static cmaper_err_t cmaper_scan_write_bytes_to_file(const char *path,
                                                    const char *data,
                                                    size_t size) {
  FILE *file;

  if (path == NULL || path[0] == '\0' || data == NULL || size == 0U) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  file = fopen(path, "wb");
  if (file == NULL) {
    return CMAPER_ERR_IO;
  }

  if (fwrite(data, 1, size, file) != size) {
    fclose(file);
    return CMAPER_ERR_IO;
  }

  if (fclose(file) != 0) {
    return CMAPER_ERR_IO;
  }

  return CMAPER_OK;
}

static int
cmaper_scan_detail_phase_hard_timeout_seconds(const cmaper_scan_plan_t *plan,
                                              const char *phase_label) {
  int timeout_seconds = 0;
  cmaper_scan_profile_t profile = CMAPER_SCAN_PROFILE_MID;

  if (plan != NULL) {
    profile = plan->profile;
  }

  if (phase_label != NULL && strncmp(phase_label, "detail-probe", 12) == 0) {
    switch (profile) {
    case CMAPER_SCAN_PROFILE_LOW:
      timeout_seconds = 420;
      break;
    case CMAPER_SCAN_PROFILE_MID:
      timeout_seconds = 420;
      break;
    case CMAPER_SCAN_PROFILE_HIGH:
      timeout_seconds = 600;
      break;
    case CMAPER_SCAN_PROFILE_UNSET:
      timeout_seconds = 420;
      break;
    }
  } else {
    switch (profile) {
    case CMAPER_SCAN_PROFILE_LOW:
      timeout_seconds = 300;
      break;
    case CMAPER_SCAN_PROFILE_MID:
      timeout_seconds = 540;
      break;
    case CMAPER_SCAN_PROFILE_HIGH:
      timeout_seconds = 780;
      break;
    case CMAPER_SCAN_PROFILE_UNSET:
      timeout_seconds = 540;
      break;
    }
  }

  if (plan != NULL && plan->all_ports) {
    timeout_seconds += 480;
  }

  return timeout_seconds;
}

cmaper_err_t cmaper_scan_detail_run_command(
    const cmaper_scan_detail_request_t *request,
    const cmaper_scan_detail_command_t *command, const char *phase_label,
    int heartbeat_seconds, const char *xml_output_path, char **out_stderr_data,
    size_t *out_stderr_size) {
  cmaper_scan_process_request_t process_request;
  cmaper_scan_process_result_t process_result;
  cmaper_scan_process_run_fn backend;
  cmaper_err_t rc;

  if (request == NULL || command == NULL || xml_output_path == NULL ||
      xml_output_path[0] == '\0' || out_stderr_data == NULL ||
      out_stderr_size == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  *out_stderr_data = NULL;
  *out_stderr_size = 0;

  backend = request->process_backend != NULL ? request->process_backend
                                             : cmaper_scan_process_run;

  process_request.program_path = command->argv[0];
  process_request.argv = command->argv;
  process_request.heartbeat_seconds = heartbeat_seconds;
  process_request.heartbeat_label = phase_label;
  process_request.hard_timeout_seconds =
      cmaper_scan_detail_phase_hard_timeout_seconds(request->plan, phase_label);

  cmaper_scan_process_result_init(&process_result);
  rc = backend(&process_request, request->logger, &process_result);
  if (rc != CMAPER_OK) {
    return rc;
  }

  if (process_result.exit_code != 0) {
    cmaper_log(request->logger, CMAPER_LOG_WARN,
               "scan/detail: %s exited with code %d", phase_label,
               process_result.exit_code);
    if (process_result.stderr_data != NULL &&
        process_result.stderr_data[0] != '\0') {
      cmaper_log(request->logger, CMAPER_LOG_WARN,
                 "scan/detail: %s stderr => %.256s", phase_label,
                 process_result.stderr_data);
    }
    cmaper_scan_process_result_dispose(&process_result);
    return CMAPER_ERR_INTERNAL;
  }

  *out_stderr_data = process_result.stderr_data;
  *out_stderr_size = process_result.stderr_size;
  process_result.stderr_data = NULL;
  process_result.stderr_size = 0;

  if (!cmaper_fs_path_exists(xml_output_path) &&
      process_result.stdout_data != NULL && process_result.stdout_size > 0U) {
    (void)cmaper_scan_write_bytes_to_file(xml_output_path,
                                          process_result.stdout_data,
                                          process_result.stdout_size);
  }

  if (!cmaper_fs_path_exists(xml_output_path)) {
    cmaper_scan_process_result_dispose(&process_result);
    return CMAPER_ERR_IO;
  }

  cmaper_scan_process_result_dispose(&process_result);
  return CMAPER_OK;
}
