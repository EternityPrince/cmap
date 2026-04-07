#include "cmaper/scan/internal/detail_internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmaper/platform/fs.h"
#include "cmaper/scan/internal/detail_target_internal.h"

static void
cmaper_scan_detail_host_message_setf(cmaper_scan_detail_host_result_t *host,
                                     const char *fmt, ...) {
  va_list args;

  if (host == NULL || fmt == NULL) {
    return;
  }

  va_start(args, fmt);
  vsnprintf(host->message, sizeof(host->message), fmt, args);
  va_end(args);
}

static void cmaper_scan_detail_sanitize_component(const char *input,
                                                  char *output,
                                                  size_t output_cap) {
  size_t i;
  size_t j = 0;

  if (output == NULL || output_cap == 0U) {
    return;
  }

  output[0] = '\0';
  if (input == NULL || input[0] == '\0') {
    return;
  }

  for (i = 0; input[i] != '\0' && j + 1U < output_cap; ++i) {
    unsigned char ch = (unsigned char)input[i];
    if ((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') ||
        (ch >= 'a' && ch <= 'z') || ch == '-' || ch == '_' || ch == '.') {
      output[j++] = (char)ch;
    } else {
      output[j++] = '_';
    }
  }
  output[j] = '\0';
}

static cmaper_err_t cmaper_scan_detail_make_temp_xml_path(
    const cmaper_scan_detail_request_t *request, const char *ip,
    size_t target_index, const char *phase, char *out_path,
    size_t out_path_cap) {
  char ip_component[CMAPER_SCAN_DETAIL_TARGET_IP_CAP * 2U];
  int written;

  if (request == NULL || request->paths == NULL || ip == NULL ||
      phase == NULL || out_path == NULL || out_path_cap == 0U) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  if (request->paths->xml_output_dir[0] == '\0') {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  if (cmaper_fs_ensure_directory_recursive(request->paths->xml_output_dir) !=
      CMAPER_OK) {
    return CMAPER_ERR_IO;
  }

  cmaper_scan_detail_sanitize_component(ip, ip_component, sizeof(ip_component));
  if (ip_component[0] == '\0') {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  written = snprintf(out_path, out_path_cap, "%s/.tmp-detail-%zu-%s-%s.xml",
                     request->paths->xml_output_dir, target_index, phase,
                     ip_component);
  if (written < 0 || (size_t)written >= out_path_cap) {
    return CMAPER_ERR_IO;
  }

  return CMAPER_OK;
}

static cmaper_err_t cmaper_scan_detail_save_final_xml(
    const cmaper_scan_detail_request_t *request, const char *ip,
    const char *source_path, cmaper_scan_detail_host_result_t *host_result) {
  cmaper_err_t rc;

  if (request == NULL || ip == NULL || source_path == NULL ||
      host_result == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  rc = cmaper_scan_artifact_save_host_xml_file(
      request->paths, request->artifact_policy, ip, source_path,
      host_result->xml_path, sizeof(host_result->xml_path));
  if (rc != CMAPER_OK) {
    host_result->xml_saved = false;
    return rc;
  }

  host_result->xml_saved = request->artifact_policy != NULL &&
                           request->artifact_policy->save_host_xml;
  return CMAPER_OK;
}

static int cmaper_scan_detail_port_compare(const void *left,
                                           const void *right) {
  int a = *((const int *)left);
  int b = *((const int *)right);

  if (a < b) {
    return -1;
  }
  if (a > b) {
    return 1;
  }
  return 0;
}

static cmaper_err_t cmaper_scan_detail_merge_open_tcp_ports(
    const int *base_ports, size_t base_port_count, const int *extra_ports,
    size_t extra_port_count, int **out_ports, size_t *out_port_count) {
  size_t total_count = 0;
  size_t write_index = 0;
  int *merged = NULL;
  size_t i;

  if (out_ports == NULL || out_port_count == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  *out_ports = NULL;
  *out_port_count = 0;

  if ((base_port_count > 0 && base_ports == NULL) ||
      (extra_port_count > 0 && extra_ports == NULL)) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  total_count = base_port_count + extra_port_count;
  if (total_count == 0U) {
    return CMAPER_OK;
  }

  merged = (int *)malloc(total_count * sizeof(int));
  if (merged == NULL) {
    return CMAPER_ERR_OOM;
  }

  for (i = 0; i < base_port_count; ++i) {
    merged[write_index++] = base_ports[i];
  }
  for (i = 0; i < extra_port_count; ++i) {
    merged[write_index++] = extra_ports[i];
  }

  qsort(merged, write_index, sizeof(int), cmaper_scan_detail_port_compare);

  total_count = 0U;
  for (i = 0; i < write_index; ++i) {
    if (merged[i] <= 0) {
      continue;
    }
    if (total_count == 0U || merged[total_count - 1U] != merged[i]) {
      merged[total_count++] = merged[i];
    }
  }

  if (total_count == 0U) {
    free(merged);
    return CMAPER_OK;
  }

  if (total_count < write_index) {
    int *shrunk = (int *)realloc(merged, total_count * sizeof(int));
    if (shrunk != NULL) {
      merged = shrunk;
    }
  }

  *out_ports = merged;
  *out_port_count = total_count;
  return CMAPER_OK;
}

void cmaper_scan_detail_execute_for_target(
    const cmaper_scan_detail_request_t *request,
    const cmaper_scan_detail_target_t *target, size_t target_index,
    cmaper_scan_detail_host_result_t *host_result,
    cmaper_scan_detail_progress_state_t *progress_state) {
  cmaper_scan_detail_spoof_policy_t spoof_policy;
  cmaper_scan_detail_command_t command;
  char final_xml_path[CMAPER_SCAN_ARTIFACT_PATH_CAP];
  char direct_xml_path[CMAPER_SCAN_ARTIFACT_PATH_CAP];
  char probe_xml_path[CMAPER_SCAN_ARTIFACT_PATH_CAP];
  char connect_probe_xml_path[CMAPER_SCAN_ARTIFACT_PATH_CAP];
  char all_probe_xml_path[CMAPER_SCAN_ARTIFACT_PATH_CAP];
  char all_connect_probe_xml_path[CMAPER_SCAN_ARTIFACT_PATH_CAP];
  char enrichment_xml_path[CMAPER_SCAN_ARTIFACT_PATH_CAP];
  char *stderr_data = NULL;
  size_t stderr_size = 0;
  int *probe_ports = NULL;
  size_t probe_port_count = 0;
  int *effective_ports = NULL;
  size_t effective_port_count = 0;
  size_t scripts_count = 0;
  int heartbeat_seconds = 15;
  cmaper_err_t rc;

  if (request == NULL || target == NULL || host_result == NULL) {
    return;
  }

  final_xml_path[0] = '\0';
  direct_xml_path[0] = '\0';
  probe_xml_path[0] = '\0';
  connect_probe_xml_path[0] = '\0';
  all_probe_xml_path[0] = '\0';
  all_connect_probe_xml_path[0] = '\0';
  enrichment_xml_path[0] = '\0';

  snprintf(host_result->ip, sizeof(host_result->ip), "%s", target->ip);

  cmaper_scan_detail_spoof_policy_resolve(
      request->plan, request->source_identity, &spoof_policy);
  if (progress_state != NULL && progress_state->dynamic_render) {
    heartbeat_seconds = 0;
  }

  if (target->has_open_tcp_ports && request->plan != NULL &&
      (request->plan->all_ports || (request->plan->exact_ports != NULL &&
                                    request->plan->exact_ports[0] != '\0'))) {
    host_result->direct_scan_attempted = true;
    cmaper_scan_detail_progress_mark_stage(progress_state, target_index,
                                           CMAPER_SCAN_DETAIL_STAGE_DIRECT);
    cmaper_scan_detail_progress_set_open_ports(progress_state, target_index,
                                               target->open_tcp_port_count);

    rc = cmaper_scan_detail_make_temp_xml_path(
        request, target->ip, target_index, "direct", direct_xml_path,
        sizeof(direct_xml_path));
    if (rc != CMAPER_OK) {
      cmaper_scan_detail_host_message_setf(host_result,
                                           "failed to prepare direct xml path");
      cmaper_scan_detail_progress_mark_stage(progress_state, target_index,
                                             CMAPER_SCAN_DETAIL_STAGE_FAILED);
      goto cleanup;
    }

    rc = cmaper_scan_detail_build_enrichment_like_command(
        request, target->ip, target->open_tcp_ports,
        target->open_tcp_port_count, direct_xml_path, &spoof_policy, &command);
    if (rc != CMAPER_OK) {
      cmaper_scan_detail_host_message_setf(
          host_result, "failed to build direct detail command");
      cmaper_scan_detail_progress_mark_stage(progress_state, target_index,
                                             CMAPER_SCAN_DETAIL_STAGE_FAILED);
      goto cleanup;
    }

    if (progress_state == NULL || !progress_state->dynamic_render) {
      cmaper_log(request->logger, CMAPER_LOG_INFO,
                 "scan/detail[%s]: direct command => %s", target->ip,
                 command.rendered);
    }

    rc = cmaper_scan_detail_run_command(request, &command, "detail-direct",
                                        heartbeat_seconds, direct_xml_path,
                                        &stderr_data, &stderr_size);
    if (stderr_data != NULL) {
      free(stderr_data);
      stderr_data = NULL;
    }
    if (rc != CMAPER_OK) {
      cmaper_scan_detail_host_message_setf(host_result,
                                           "direct detail scan failed");
      cmaper_scan_detail_progress_mark_stage(progress_state, target_index,
                                             CMAPER_SCAN_DETAIL_STAGE_FAILED);
      goto cleanup;
    }

    host_result->direct_scan_success = true;
    host_result->success = true;
    snprintf(final_xml_path, sizeof(final_xml_path), "%s", direct_xml_path);
  } else {
    host_result->probe_attempted = true;
    cmaper_scan_detail_progress_mark_stage(progress_state, target_index,
                                           CMAPER_SCAN_DETAIL_STAGE_PROBE);

    rc = cmaper_scan_detail_make_temp_xml_path(
        request, target->ip, target_index, "probe", probe_xml_path,
        sizeof(probe_xml_path));
    if (rc != CMAPER_OK) {
      cmaper_scan_detail_host_message_setf(host_result,
                                           "failed to prepare probe xml path");
      cmaper_scan_detail_progress_mark_stage(progress_state, target_index,
                                             CMAPER_SCAN_DETAIL_STAGE_FAILED);
      goto cleanup;
    }

    rc = cmaper_scan_detail_build_probe_command(request, target, probe_xml_path,
                                                &spoof_policy, &command);
    if (rc != CMAPER_OK) {
      cmaper_scan_detail_host_message_setf(host_result,
                                           "failed to build probe command");
      cmaper_scan_detail_progress_mark_stage(progress_state, target_index,
                                             CMAPER_SCAN_DETAIL_STAGE_FAILED);
      goto cleanup;
    }

    if (progress_state == NULL || !progress_state->dynamic_render) {
      cmaper_log(request->logger, CMAPER_LOG_INFO,
                 "scan/detail[%s]: probe command => %s", target->ip,
                 command.rendered);
    }

    rc = cmaper_scan_detail_run_command(request, &command, "detail-probe",
                                        heartbeat_seconds, probe_xml_path,
                                        &stderr_data, &stderr_size);
    if (stderr_data != NULL) {
      free(stderr_data);
      stderr_data = NULL;
    }
    if (rc != CMAPER_OK) {
      cmaper_scan_detail_host_message_setf(host_result, "probe scan failed");
      cmaper_scan_detail_progress_mark_stage(progress_state, target_index,
                                             CMAPER_SCAN_DETAIL_STAGE_FAILED);
      goto cleanup;
    }

    host_result->probe_success = true;
    snprintf(final_xml_path, sizeof(final_xml_path), "%s", probe_xml_path);

    rc = cmaper_scan_detail_target_extract_probe_ports(
        final_xml_path, target->ip, &probe_ports, &probe_port_count);
    if (rc == CMAPER_OK && probe_port_count == 0 && request->plan != NULL &&
        request->plan->sudo) {
      int *connect_probe_ports = NULL;
      size_t connect_probe_port_count = 0;
      cmaper_err_t fallback_rc;

      fallback_rc = cmaper_scan_detail_make_temp_xml_path(
          request, target->ip, target_index, "probe-connect",
          connect_probe_xml_path, sizeof(connect_probe_xml_path));

      if (fallback_rc != CMAPER_OK) {
        connect_probe_xml_path[0] = '\0';
      }

      if (fallback_rc == CMAPER_OK) {
        fallback_rc = cmaper_scan_detail_build_probe_command_with_transport(
            request, target, CMAPER_SCAN_DETAIL_PROBE_TRANSPORT_TCP_CONNECT,
            connect_probe_xml_path, &spoof_policy, &command);
      }
      if (fallback_rc == CMAPER_OK) {
        if (progress_state == NULL || !progress_state->dynamic_render) {
          cmaper_log(request->logger, CMAPER_LOG_INFO,
                     "scan/detail[%s]: probe fallback command => %s",
                     target->ip, command.rendered);
        }

        fallback_rc = cmaper_scan_detail_run_command(
            request, &command, "detail-probe-connect", heartbeat_seconds,
            connect_probe_xml_path, &stderr_data, &stderr_size);
        if (stderr_data != NULL) {
          free(stderr_data);
          stderr_data = NULL;
        }
      }

      if (fallback_rc == CMAPER_OK && connect_probe_xml_path[0] != '\0') {
        fallback_rc = cmaper_scan_detail_target_extract_probe_ports(
            connect_probe_xml_path, target->ip, &connect_probe_ports,
            &connect_probe_port_count);
        if (fallback_rc == CMAPER_OK) {
          snprintf(final_xml_path, sizeof(final_xml_path), "%s",
                   connect_probe_xml_path);

          if (probe_ports != NULL) {
            free(probe_ports);
          }
          probe_ports = connect_probe_ports;
          probe_port_count = connect_probe_port_count;
          connect_probe_ports = NULL;
          connect_probe_port_count = 0;

          if (probe_port_count > 0) {
            cmaper_log(request->logger, CMAPER_LOG_WARN,
                       "scan/detail[%s]: probe fallback (-sT) recovered %zu "
                       "open tcp ports",
                       target->ip, probe_port_count);
          }
        }
      }

      if (connect_probe_ports != NULL) {
        free(connect_probe_ports);
      }
    }

    if (rc == CMAPER_OK && probe_port_count == 0 && request->plan != NULL &&
        !request->plan->all_ports &&
        (request->plan->exact_ports == NULL ||
         request->plan->exact_ports[0] == '\0')) {
      cmaper_scan_plan_t probe_all_plan;
      cmaper_scan_detail_request_t probe_all_request;
      int *all_probe_ports = NULL;
      size_t all_probe_port_count = 0;
      cmaper_err_t fallback_rc;

      probe_all_plan = *request->plan;
      probe_all_plan.all_ports = true;
      probe_all_request = *request;
      probe_all_request.plan = &probe_all_plan;

      fallback_rc = cmaper_scan_detail_make_temp_xml_path(
          request, target->ip, target_index, "probe-all", all_probe_xml_path,
          sizeof(all_probe_xml_path));
      if (fallback_rc == CMAPER_OK) {
        fallback_rc = cmaper_scan_detail_build_probe_command(
            &probe_all_request, target, all_probe_xml_path, &spoof_policy,
            &command);
      }
      if (fallback_rc == CMAPER_OK) {
        if (progress_state == NULL || !progress_state->dynamic_render) {
          cmaper_log(
              request->logger, CMAPER_LOG_INFO,
              "scan/detail[%s]: probe fallback command (full tcp range) => %s",
              target->ip, command.rendered);
        }

        fallback_rc = cmaper_scan_detail_run_command(
            request, &command, "detail-probe-all", heartbeat_seconds,
            all_probe_xml_path, &stderr_data, &stderr_size);
        if (stderr_data != NULL) {
          free(stderr_data);
          stderr_data = NULL;
        }
      }

      if (fallback_rc == CMAPER_OK) {
        fallback_rc = cmaper_scan_detail_target_extract_probe_ports(
            all_probe_xml_path, target->ip, &all_probe_ports,
            &all_probe_port_count);
        if (fallback_rc == CMAPER_OK) {
          snprintf(final_xml_path, sizeof(final_xml_path), "%s",
                   all_probe_xml_path);
        }
      }

      if (fallback_rc == CMAPER_OK && all_probe_port_count == 0 &&
          request->plan->sudo) {
        int *all_connect_ports = NULL;
        size_t all_connect_port_count = 0;

        fallback_rc = cmaper_scan_detail_make_temp_xml_path(
            request, target->ip, target_index, "probe-all-connect",
            all_connect_probe_xml_path, sizeof(all_connect_probe_xml_path));

        if (fallback_rc == CMAPER_OK) {
          fallback_rc = cmaper_scan_detail_build_probe_command_with_transport(
              &probe_all_request, target,
              CMAPER_SCAN_DETAIL_PROBE_TRANSPORT_TCP_CONNECT,
              all_connect_probe_xml_path, &spoof_policy, &command);
        }

        if (fallback_rc == CMAPER_OK) {
          if (progress_state == NULL || !progress_state->dynamic_render) {
            cmaper_log(request->logger, CMAPER_LOG_INFO,
                       "scan/detail[%s]: probe fallback command (full tcp "
                       "range -sT) => %s",
                       target->ip, command.rendered);
          }

          fallback_rc = cmaper_scan_detail_run_command(
              request, &command, "detail-probe-all-connect", heartbeat_seconds,
              all_connect_probe_xml_path, &stderr_data, &stderr_size);
          if (stderr_data != NULL) {
            free(stderr_data);
            stderr_data = NULL;
          }
        }

        if (fallback_rc == CMAPER_OK) {
          fallback_rc = cmaper_scan_detail_target_extract_probe_ports(
              all_connect_probe_xml_path, target->ip, &all_connect_ports,
              &all_connect_port_count);
          if (fallback_rc == CMAPER_OK) {
            if (all_probe_ports != NULL) {
              free(all_probe_ports);
            }
            all_probe_ports = all_connect_ports;
            all_probe_port_count = all_connect_port_count;
            all_connect_ports = NULL;
            all_connect_port_count = 0;
            snprintf(final_xml_path, sizeof(final_xml_path), "%s",
                     all_connect_probe_xml_path);
          }
        }

        if (all_connect_ports != NULL) {
          free(all_connect_ports);
        }
      }

      if (fallback_rc == CMAPER_OK && all_probe_port_count > 0) {
        if (probe_ports != NULL) {
          free(probe_ports);
        }
        probe_ports = all_probe_ports;
        probe_port_count = all_probe_port_count;
        all_probe_ports = NULL;

        cmaper_log(
            request->logger, CMAPER_LOG_WARN,
            "scan/detail[%s]: full-range probe recovered %zu open tcp ports",
            target->ip, probe_port_count);
      }

      if (all_probe_ports != NULL) {
        free(all_probe_ports);
      }
    }

    effective_ports = probe_ports;
    effective_port_count = probe_port_count;

    if (rc == CMAPER_OK && target->has_open_tcp_ports &&
        request->plan != NULL && !request->plan->all_ports &&
        (request->plan->exact_ports == NULL ||
         request->plan->exact_ports[0] == '\0')) {
      rc = cmaper_scan_detail_merge_open_tcp_ports(
          target->open_tcp_ports, target->open_tcp_port_count, probe_ports,
          probe_port_count, &effective_ports, &effective_port_count);
    }

    if (rc != CMAPER_OK) {
      host_result->used_probe_xml_as_final = true;
      host_result->success = true;
      cmaper_scan_detail_host_message_setf(
          host_result, "probe xml parse failed, using probe xml as final");
    } else if (effective_port_count > 0) {
      cmaper_scan_detail_progress_set_open_ports(progress_state, target_index,
                                                 effective_port_count);

      host_result->enrichment_attempted = true;
      cmaper_scan_detail_progress_mark_stage(
          progress_state, target_index, CMAPER_SCAN_DETAIL_STAGE_ENRICHMENT);

      rc = cmaper_scan_detail_make_temp_xml_path(
          request, target->ip, target_index, "enrichment", enrichment_xml_path,
          sizeof(enrichment_xml_path));

      if (rc == CMAPER_OK) {
        rc = cmaper_scan_detail_build_enrichment_like_command(
            request, target->ip, effective_ports, effective_port_count,
            enrichment_xml_path, &spoof_policy, &command);
      }
      if (rc == CMAPER_OK) {
        if (progress_state == NULL || !progress_state->dynamic_render) {
          cmaper_log(request->logger, CMAPER_LOG_INFO,
                     "scan/detail[%s]: enrichment command => %s", target->ip,
                     command.rendered);
        }

        rc = cmaper_scan_detail_run_command(
            request, &command, "detail-enrichment", heartbeat_seconds,
            enrichment_xml_path, &stderr_data, &stderr_size);
        if (stderr_data != NULL) {
          free(stderr_data);
          stderr_data = NULL;
        }
      }

      if (rc == CMAPER_OK && enrichment_xml_path[0] != '\0') {
        host_result->enrichment_success = true;
        snprintf(final_xml_path, sizeof(final_xml_path), "%s",
                 enrichment_xml_path);
      } else {
        host_result->used_probe_xml_as_final = true;
        host_result->success = true;
        cmaper_scan_detail_host_message_setf(
            host_result, "enrichment failed, probe xml kept as final");
      }
    } else {
      cmaper_scan_detail_progress_set_open_ports(progress_state, target_index,
                                                 0);
      host_result->success = true;
      cmaper_scan_detail_host_message_setf(
          host_result, "probe completed with no open tcp ports");
    }

    if (effective_ports != NULL && effective_ports != probe_ports) {
      free(effective_ports);
      effective_ports = NULL;
    }
    if (probe_ports != NULL) {
      free(probe_ports);
      probe_ports = NULL;
    }
    effective_ports = NULL;
    effective_port_count = 0;

    if (!host_result->success && final_xml_path[0] != '\0') {
      host_result->success = true;
    }
  }

  if (host_result->success && final_xml_path[0] != '\0') {
    if (cmaper_scan_detail_target_count_scripts(final_xml_path, target->ip,
                                                &scripts_count)) {
      cmaper_scan_detail_progress_set_scripts(progress_state, target_index,
                                              scripts_count);
    }

    rc = cmaper_scan_detail_save_final_xml(request, target->ip, final_xml_path,
                                           host_result);
    if (rc != CMAPER_OK) {
      cmaper_scan_detail_host_message_setf(host_result,
                                           "final xml save failed");
      host_result->success = false;
    }
  }

  if (host_result->success) {
    if (host_result->used_probe_xml_as_final ||
        (host_result->enrichment_attempted &&
         !host_result->enrichment_success)) {
      cmaper_scan_detail_progress_mark_stage(progress_state, target_index,
                                             CMAPER_SCAN_DETAIL_STAGE_DEGRADED);
    } else {
      cmaper_scan_detail_progress_mark_stage(progress_state, target_index,
                                             CMAPER_SCAN_DETAIL_STAGE_DONE);
    }
  } else {
    cmaper_scan_detail_progress_mark_stage(progress_state, target_index,
                                           CMAPER_SCAN_DETAIL_STAGE_FAILED);
  }

cleanup:
  if (stderr_data != NULL) {
    free(stderr_data);
  }
  if (effective_ports != NULL && effective_ports != probe_ports) {
    free(effective_ports);
  }
  if (probe_ports != NULL) {
    free(probe_ports);
  }
  if (direct_xml_path[0] != '\0') {
    (void)remove(direct_xml_path);
  }
  if (probe_xml_path[0] != '\0') {
    (void)remove(probe_xml_path);
  }
  if (connect_probe_xml_path[0] != '\0') {
    (void)remove(connect_probe_xml_path);
  }
  if (all_probe_xml_path[0] != '\0') {
    (void)remove(all_probe_xml_path);
  }
  if (all_connect_probe_xml_path[0] != '\0') {
    (void)remove(all_connect_probe_xml_path);
  }
  if (enrichment_xml_path[0] != '\0') {
    (void)remove(enrichment_xml_path);
  }
}
