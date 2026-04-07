#include "cmaper/scan/runner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "cmaper/platform/fs.h"
#include "cmaper/scan/nmap_xml_parse.h"

#define CMAPER_SCAN_SUDO_BIN_PATH "/usr/bin/sudo"

static void cmaper_scan_make_default_session_id(char *out, size_t out_cap) {
  time_t now;

  if (out == NULL || out_cap == 0) {
    return;
  }

  now = time(NULL);
  snprintf(out, out_cap, "session-%lld", (long long)now);
}

static cmaper_err_t
cmaper_scan_make_temp_xml_path(const cmaper_runtime_paths_t *paths,
                               const char *prefix, char *out_path,
                               size_t out_path_cap) {
  int written;
  long pid;
  long long now_epoch;

  if (paths == NULL || prefix == NULL || prefix[0] == '\0' ||
      out_path == NULL || out_path_cap == 0) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  if (paths->xml_output_dir[0] == '\0') {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  if (cmaper_fs_ensure_directory_recursive(paths->xml_output_dir) !=
      CMAPER_OK) {
    return CMAPER_ERR_IO;
  }

  pid = (long)getpid();
  now_epoch = (long long)time(NULL);
  written = snprintf(out_path, out_path_cap, "%s/.tmp-%s-%lld-%ld.xml",
                     paths->xml_output_dir, prefix, now_epoch, pid);
  if (written < 0 || (size_t)written >= out_path_cap) {
    return CMAPER_ERR_IO;
  }

  return CMAPER_OK;
}

static cmaper_err_t
cmaper_scan_command_set_xml_output(cmaper_scan_command_t *command,
                                   const char *output_path,
                                   cmaper_scan_command_diag_t *diag) {
  size_t i;
  size_t output_index = (size_t)-1;
  int written;

  if (command == NULL || output_path == NULL || output_path[0] == '\0') {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  for (i = 0; i + 1U < (size_t)command->argc; ++i) {
    if (command->argv[i] != NULL && strcmp(command->argv[i], "-oX") == 0) {
      output_index = i + 1U;
      break;
    }
  }

  if (output_index == (size_t)-1) {
    if (command->argc >= 4 && command->argv[0] != NULL &&
        strcmp(command->argv[0], CMAPER_SCAN_SUDO_BIN_PATH) == 0 &&
        command->argc >= 5) {
      output_index = 4U;
    } else if (command->argc >= 4) {
      output_index = 3U;
    }
  }

  if (output_index != (size_t)-1 && output_index < (size_t)command->argc) {
    written =
        snprintf(command->arg_data[output_index],
                 sizeof(command->arg_data[output_index]), "%s", output_path);
    if (written < 0 ||
        written >= (int)sizeof(command->arg_data[output_index])) {
      cmaper_scan_command_diag_setf(diag, "argv",
                                    "xml output path is too long");
      return CMAPER_ERR_IO;
    }

    command->argv[output_index] = command->arg_data[output_index];
    command->rendered[0] = '\0';
    for (i = 0; i < (size_t)command->argc; ++i) {
      int render_written;
      size_t used = strlen(command->rendered);
      const char *prefix = i == 0 ? "" : " ";

      render_written =
          snprintf(command->rendered + used, sizeof(command->rendered) - used,
                   "%s%s", prefix, command->argv[i]);
      if (render_written < 0 ||
          (size_t)render_written >= (sizeof(command->rendered) - used)) {
        command->rendered[sizeof(command->rendered) - 1U] = '\0';
        break;
      }
    }

    return CMAPER_OK;
  }

  cmaper_scan_command_diag_setf(diag, "argv",
                                "failed to locate -oX argument in command");
  return CMAPER_ERR_INTERNAL;
}

static size_t cmaper_scan_file_size_or_zero(const char *path) {
  FILE *file;
  long size;

  if (path == NULL || path[0] == '\0') {
    return 0U;
  }

  file = fopen(path, "rb");
  if (file == NULL) {
    return 0U;
  }
  if (fseek(file, 0, SEEK_END) != 0) {
    fclose(file);
    return 0U;
  }
  size = ftell(file);
  fclose(file);

  if (size <= 0) {
    return 0U;
  }
  return (size_t)size;
}

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

void cmaper_scan_request_init(cmaper_scan_request_t *request) {
  if (request == NULL) {
    return;
  }

  request->plan = NULL;
  request->save_discovery_xml = false;
  request->save_host_xml = false;
  request->session_id = NULL;
  request->process_backend = NULL;
}

void cmaper_scan_result_init(cmaper_scan_result_t *result) {
  if (result == NULL) {
    return;
  }

  cmaper_scan_source_identity_init(&result->source_identity);
  cmaper_scan_discovery_plan_init(&result->discovery_plan);
  cmaper_scan_command_init(&result->discovery_command);
  result->discovery_xml = NULL;
  result->discovery_xml_size = 0;
  result->process_stderr = NULL;
  result->process_stderr_size = 0;
  result->discovery_xml_saved = false;
  result->discovery_xml_path[0] = '\0';
  result->session_id[0] = '\0';
  cmaper_scan_detail_targets_init(&result->detail_targets);
  cmaper_scan_detail_result_init(&result->detail_result);
}

void cmaper_scan_result_dispose(cmaper_scan_result_t *result) {
  if (result == NULL) {
    return;
  }

  if (result->discovery_xml != NULL) {
    free(result->discovery_xml);
    result->discovery_xml = NULL;
  }
  result->discovery_xml_size = 0;

  if (result->process_stderr != NULL) {
    free(result->process_stderr);
    result->process_stderr = NULL;
  }
  result->process_stderr_size = 0;

  result->discovery_xml_saved = false;
  result->discovery_xml_path[0] = '\0';
  result->session_id[0] = '\0';

  cmaper_scan_detail_targets_dispose(&result->detail_targets);
  cmaper_scan_detail_result_dispose(&result->detail_result);
}

void cmaper_scan_result_render_summary(FILE *stream,
                                       const cmaper_scan_result_t *result) {
  const char *xml_path = "(not saved)";
  const char *session_id = "(none)";

  if (stream == NULL || result == NULL) {
    return;
  }

  if (result->discovery_xml_saved && result->discovery_xml_path[0] != '\0') {
    xml_path = result->discovery_xml_path;
  }
  if (result->session_id[0] != '\0') {
    session_id = result->session_id;
  }

  fprintf(
      stream,
      "Scan session result:\n"
      "  session-id: %s\n"
      "Discovery:\n"
      "  representative-target: %s\n"
      "  source-identity: %s\n"
      "  discovery-kind: %s\n"
      "  transport: %s\n"
      "  spoofing: %s\n"
      "  spoofing-suppression: %s\n"
      "  xml-bytes: %zu\n"
      "  discovery-xml-saved: %s\n"
      "  discovery-xml-path: %s\n"
      "Detail:\n"
      "  targets-total: %zu\n"
      "  hosts-success: %zu\n"
      "  hosts-failed: %zu\n"
      "  hosts-degraded: %zu\n",
      session_id,
      result->source_identity.representative_target[0] != '\0'
          ? result->source_identity.representative_target
          : "(unknown)",
      cmaper_scan_source_identity_mode_name(result->source_identity.mode),
      cmaper_discovery_kind_name(result->discovery_plan.kind),
      cmaper_discovery_transport_name(result->discovery_plan.transport),
      result->discovery_plan.spoof_applied ? "applied" : "suppressed",
      cmaper_spoof_suppression_name(result->discovery_plan.spoof_suppression),
      result->discovery_xml_size, result->discovery_xml_saved ? "yes" : "no",
      xml_path, result->detail_targets.count,
      result->detail_result.successful_hosts,
      result->detail_result.failed_hosts, result->detail_result.degraded_hosts);
}

cmaper_err_t cmaper_scan_runner_run(cmaper_runtime_t *runtime,
                                    const cmaper_scan_request_t *request,
                                    cmaper_scan_result_t *result) {
  cmaper_scan_process_request_t process_request;
  cmaper_scan_process_result_t process_result;
  cmaper_scan_artifact_policy_t artifact_policy;
  cmaper_scan_command_diag_t command_diag;
  cmaper_nmap_xml_diag_t xml_diag;
  cmaper_scan_detail_target_diag_t target_diag;
  cmaper_nmap_xml_document_t discovery_document;
  cmaper_scan_detail_request_t detail_request;
  cmaper_scan_process_run_fn process_backend;
  cmaper_err_t rc;
  char generated_session_id[64];
  char discovery_temp_xml_path[CMAPER_SCAN_ARTIFACT_PATH_CAP];
  bool discovery_temp_xml_exists = false;
  const char *session_id = NULL;

  if (runtime == NULL || request == NULL || request->plan == NULL ||
      result == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  cmaper_scan_result_dispose(result);
  cmaper_scan_result_init(result);
  cmaper_scan_process_result_init(&process_result);
  cmaper_scan_command_diag_clear(&command_diag);
  cmaper_nmap_xml_diag_clear(&xml_diag);
  cmaper_scan_detail_target_diag_clear(&target_diag);
  cmaper_nmap_xml_document_init(&discovery_document);
  discovery_temp_xml_path[0] = '\0';

  cmaper_log(&runtime->logger, CMAPER_LOG_PHASE,
             "scan/discovery: resolving source identity");
  rc = cmaper_scan_source_identity_resolve(request->plan,
                                           &result->source_identity);
  if (rc != CMAPER_OK) {
    cmaper_log(&runtime->logger, CMAPER_LOG_FAIL,
               "scan/discovery: source identity resolve failed");
    goto cleanup;
  }

  cmaper_log(&runtime->logger, CMAPER_LOG_INFO,
             "scan/discovery: representative target '%s' (cidr=%s loopback=%s)",
             result->source_identity.representative_target,
             result->source_identity.representative_is_cidr ? "yes" : "no",
             result->source_identity.representative_is_loopback ? "yes" : "no");

  cmaper_log(&runtime->logger, CMAPER_LOG_PHASE,
             "scan/discovery: planning command");
  rc = cmaper_scan_discovery_plan_build(request->plan, &result->source_identity,
                                        &result->discovery_plan, &command_diag);
  if (rc != CMAPER_OK) {
    cmaper_log(&runtime->logger, CMAPER_LOG_FAIL,
               "scan/discovery: plan build failed: %s",
               command_diag.message[0] != '\0' ? command_diag.message
                                               : "unknown error");
    goto cleanup;
  }

  generated_session_id[0] = '\0';
  session_id = request->session_id;
  if ((request->save_discovery_xml || request->save_host_xml) &&
      (session_id == NULL || session_id[0] == '\0')) {
    cmaper_scan_make_default_session_id(generated_session_id,
                                        sizeof(generated_session_id));
    session_id = generated_session_id;
    cmaper_log(&runtime->logger, CMAPER_LOG_WARN,
               "scan: session id was not provided, using '%s'", session_id);
  }

  artifact_policy.save_discovery_xml = request->save_discovery_xml;
  artifact_policy.save_host_xml = request->save_host_xml;
  artifact_policy.session_id = session_id;

  if (session_id != NULL && session_id[0] != '\0') {
    snprintf(result->session_id, sizeof(result->session_id), "%s", session_id);
  }

  rc = cmaper_scan_command_build_discovery(
      &runtime->paths, &result->discovery_plan, &result->discovery_command,
      &command_diag);
  if (rc != CMAPER_OK) {
    cmaper_log(&runtime->logger, CMAPER_LOG_FAIL,
               "scan/discovery: command build failed: %s",
               command_diag.message[0] != '\0' ? command_diag.message
                                               : "unknown error");
    goto cleanup;
  }

  rc = cmaper_scan_make_temp_xml_path(&runtime->paths, "discovery",
                                      discovery_temp_xml_path,
                                      sizeof(discovery_temp_xml_path));
  if (rc != CMAPER_OK) {
    cmaper_log(&runtime->logger, CMAPER_LOG_FAIL,
               "scan/discovery: failed to prepare temporary xml path");
    goto cleanup;
  }

  rc = cmaper_scan_command_set_xml_output(
      &result->discovery_command, discovery_temp_xml_path, &command_diag);
  if (rc != CMAPER_OK) {
    cmaper_log(&runtime->logger, CMAPER_LOG_FAIL,
               "scan/discovery: command update failed: %s",
               command_diag.message[0] != '\0' ? command_diag.message
                                               : "unknown error");
    goto cleanup;
  }

  cmaper_log(&runtime->logger, CMAPER_LOG_INFO, "scan/discovery: command => %s",
             result->discovery_command.rendered);
  if (result->discovery_plan.kind == CMAPER_DISCOVERY_KIND_HOST_DISCOVERY &&
      !result->discovery_plan.no_ping) {
    cmaper_log(&runtime->logger, CMAPER_LOG_WARN,
               "scan/discovery: host-discovery may miss silent hosts; use "
               "--no-ping for full coverage");
  }

  process_request.program_path = result->discovery_command.argv[0];
  process_request.argv = result->discovery_command.argv;
  process_request.heartbeat_seconds = 15;
  process_request.heartbeat_label = "scan/discovery";
  process_request.hard_timeout_seconds = 0;

  process_backend = request->process_backend != NULL ? request->process_backend
                                                     : cmaper_scan_process_run;

  cmaper_log(&runtime->logger, CMAPER_LOG_PHASE,
             "scan/discovery: running nmap");
  rc = process_backend(&process_request, &runtime->logger, &process_result);
  if (rc != CMAPER_OK) {
    cmaper_log(&runtime->logger, CMAPER_LOG_FAIL,
               "scan/discovery: process launch failed");
    goto cleanup;
  }

  if (process_result.exit_code != 0) {
    const char *stderr_text = process_result.stderr_data != NULL
                                  ? process_result.stderr_data
                                  : "(empty)";

    result->process_stderr = process_result.stderr_data;
    result->process_stderr_size = process_result.stderr_size;
    process_result.stderr_data = NULL;
    process_result.stderr_size = 0;

    cmaper_log(&runtime->logger, CMAPER_LOG_FAIL,
               "scan/discovery: nmap exited with code %d",
               process_result.exit_code);
    cmaper_log(&runtime->logger, CMAPER_LOG_FAIL,
               "scan/discovery: stderr => %.256s", stderr_text);
    rc = CMAPER_ERR_INTERNAL;
    goto cleanup;
  }

  result->process_stderr = process_result.stderr_data;
  result->process_stderr_size = process_result.stderr_size;
  process_result.stderr_data = NULL;
  process_result.stderr_size = 0;

  if (!cmaper_fs_path_exists(discovery_temp_xml_path) &&
      process_result.stdout_data != NULL && process_result.stdout_size > 0U) {
    (void)cmaper_scan_write_bytes_to_file(discovery_temp_xml_path,
                                          process_result.stdout_data,
                                          process_result.stdout_size);
  }

  if (!cmaper_fs_path_exists(discovery_temp_xml_path)) {
    cmaper_log(&runtime->logger, CMAPER_LOG_FAIL,
               "scan/discovery: nmap did not produce discovery xml");
    rc = CMAPER_ERR_PARSE;
    goto cleanup;
  }
  discovery_temp_xml_exists = true;
  result->discovery_xml_size =
      cmaper_scan_file_size_or_zero(discovery_temp_xml_path);

  rc = cmaper_scan_artifact_save_discovery_xml_file(
      &runtime->paths, &artifact_policy, discovery_temp_xml_path,
      result->discovery_xml_path, sizeof(result->discovery_xml_path));
  if (rc != CMAPER_OK) {
    cmaper_log(&runtime->logger, CMAPER_LOG_FAIL,
               "scan/discovery: failed to save discovery.xml artifact");
    goto cleanup;
  }
  result->discovery_xml_saved = artifact_policy.save_discovery_xml;

  rc = cmaper_nmap_xml_parse_file(discovery_temp_xml_path, &discovery_document,
                                  &xml_diag);
  if (rc != CMAPER_OK) {
    cmaper_log(&runtime->logger, CMAPER_LOG_FAIL,
               "scan/discovery: xml parse failed: %s",
               xml_diag.message[0] != '\0' ? xml_diag.message
                                           : "unknown parse error");
    rc = CMAPER_ERR_PARSE;
    goto cleanup;
  }

  rc = cmaper_scan_detail_targets_build(&discovery_document,
                                        &result->detail_targets, &target_diag);
  if (rc != CMAPER_OK) {
    cmaper_log(&runtime->logger, CMAPER_LOG_FAIL,
               "scan/detail: target extraction failed: %s",
               target_diag.message[0] != '\0' ? target_diag.message
                                              : "unknown extraction error");
    goto cleanup;
  }

  cmaper_log(&runtime->logger, CMAPER_LOG_PHASE,
             "scan/detail: %zu targets extracted",
             result->detail_targets.count);

  detail_request.plan = request->plan;
  detail_request.source_identity = &result->source_identity;
  detail_request.paths = &runtime->paths;
  detail_request.targets = &result->detail_targets;
  detail_request.artifact_policy = &artifact_policy;
  detail_request.worker_limit = request->plan->detail_workers;
  detail_request.process_backend = process_backend;
  detail_request.logger = &runtime->logger;

  rc = cmaper_scan_detail_execute(&detail_request, &result->detail_result);
  if (rc != CMAPER_OK) {
    cmaper_log(&runtime->logger, CMAPER_LOG_FAIL,
               "scan/detail: execution failed");
    goto cleanup;
  }

  cmaper_log(&runtime->logger, CMAPER_LOG_OK,
             "scan: completed (detail success=%zu failed=%zu degraded=%zu)",
             result->detail_result.successful_hosts,
             result->detail_result.failed_hosts,
             result->detail_result.degraded_hosts);

  rc = CMAPER_OK;

cleanup:
  if (discovery_temp_xml_exists) {
    (void)remove(discovery_temp_xml_path);
  }
  cmaper_nmap_xml_document_dispose(&discovery_document);
  cmaper_scan_process_result_dispose(&process_result);
  if (rc != CMAPER_OK) {
    cmaper_scan_result_dispose(result);
    cmaper_scan_result_init(result);
  }
  return rc;
}
