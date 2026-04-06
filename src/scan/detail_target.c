#include "cmaper/scan/internal/detail_internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "cmaper/scan/internal/detail_target_internal.h"

static void cmaper_scan_detail_host_message_setf(
    cmaper_scan_detail_host_result_t *host,
    const char *fmt,
    ...
) {
    va_list args;

    if (host == NULL || fmt == NULL) {
        return;
    }

    va_start(args, fmt);
    vsnprintf(host->message, sizeof(host->message), fmt, args);
    va_end(args);
}

static cmaper_err_t cmaper_scan_detail_save_final_xml(
    const cmaper_scan_detail_request_t *request,
    const char *ip,
    const char *xml_data,
    size_t xml_size,
    cmaper_scan_detail_host_result_t *host_result
) {
    cmaper_err_t rc;

    if (request == NULL || ip == NULL || xml_data == NULL || host_result == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = cmaper_scan_artifact_save_host_xml(
        request->paths,
        request->artifact_policy,
        ip,
        xml_data,
        xml_size,
        host_result->xml_path,
        sizeof(host_result->xml_path)
    );
    if (rc != CMAPER_OK) {
        host_result->xml_saved = false;
        return rc;
    }

    host_result->xml_saved = request->artifact_policy != NULL
        && request->artifact_policy->save_host_xml;
    return CMAPER_OK;
}

void cmaper_scan_detail_execute_for_target(
    const cmaper_scan_detail_request_t *request,
    const cmaper_scan_detail_target_t *target,
    size_t target_index,
    cmaper_scan_detail_host_result_t *host_result,
    cmaper_scan_detail_progress_state_t *progress_state
) {
    cmaper_scan_detail_spoof_policy_t spoof_policy;
    cmaper_scan_detail_command_t command;
    char *final_xml = NULL;
    size_t final_xml_size = 0;
    char *probe_xml = NULL;
    size_t probe_xml_size = 0;
    char *stderr_data = NULL;
    size_t stderr_size = 0;
    size_t scripts_count = 0;
    int heartbeat_seconds = 15;
    cmaper_err_t rc;

    if (request == NULL || target == NULL || host_result == NULL) {
        return;
    }

    snprintf(host_result->ip, sizeof(host_result->ip), "%s", target->ip);

    cmaper_scan_detail_spoof_policy_resolve(request->plan, request->source_identity, &spoof_policy);
    if (progress_state != NULL && progress_state->dynamic_render) {
        heartbeat_seconds = 0;
    }

    if (target->has_open_tcp_ports) {
        host_result->direct_scan_attempted = true;
        cmaper_scan_detail_progress_mark_stage(
            progress_state,
            target_index,
            CMAPER_SCAN_DETAIL_STAGE_DIRECT
        );
        cmaper_scan_detail_progress_set_open_ports(
            progress_state,
            target_index,
            target->open_tcp_port_count
        );

        rc = cmaper_scan_detail_build_enrichment_like_command(
            request,
            target->ip,
            target->open_tcp_ports,
            target->open_tcp_port_count,
            &spoof_policy,
            &command
        );
        if (rc != CMAPER_OK) {
            cmaper_scan_detail_host_message_setf(host_result, "failed to build direct detail command");
            cmaper_scan_detail_progress_mark_stage(
                progress_state,
                target_index,
                CMAPER_SCAN_DETAIL_STAGE_FAILED
            );
            return;
        }

        if (progress_state == NULL || !progress_state->dynamic_render) {
            cmaper_log(
                request->logger,
                CMAPER_LOG_INFO,
                "scan/detail[%s]: direct command => %s",
                target->ip,
                command.rendered
            );
        }

        rc = cmaper_scan_detail_run_command(
            request,
            &command,
            "detail-direct",
            heartbeat_seconds,
            &final_xml,
            &final_xml_size,
            &stderr_data,
            &stderr_size
        );
        if (stderr_data != NULL) {
            free(stderr_data);
            stderr_data = NULL;
        }
        if (rc != CMAPER_OK || final_xml == NULL || final_xml_size == 0) {
            if (final_xml != NULL) {
                free(final_xml);
            }
            cmaper_scan_detail_host_message_setf(host_result, "direct detail scan failed");
            cmaper_scan_detail_progress_mark_stage(
                progress_state,
                target_index,
                CMAPER_SCAN_DETAIL_STAGE_FAILED
            );
            return;
        }

        host_result->direct_scan_success = true;
        host_result->success = true;
    } else {
        int *probe_ports = NULL;
        size_t probe_port_count = 0;

        host_result->probe_attempted = true;
        cmaper_scan_detail_progress_mark_stage(
            progress_state,
            target_index,
            CMAPER_SCAN_DETAIL_STAGE_PROBE
        );

        rc = cmaper_scan_detail_build_probe_command(request, target, &spoof_policy, &command);
        if (rc != CMAPER_OK) {
            cmaper_scan_detail_host_message_setf(host_result, "failed to build probe command");
            cmaper_scan_detail_progress_mark_stage(
                progress_state,
                target_index,
                CMAPER_SCAN_DETAIL_STAGE_FAILED
            );
            return;
        }

        if (progress_state == NULL || !progress_state->dynamic_render) {
            cmaper_log(
                request->logger,
                CMAPER_LOG_INFO,
                "scan/detail[%s]: probe command => %s",
                target->ip,
                command.rendered
            );
        }

        rc = cmaper_scan_detail_run_command(
            request,
            &command,
            "detail-probe",
            heartbeat_seconds,
            &probe_xml,
            &probe_xml_size,
            &stderr_data,
            &stderr_size
        );
        if (stderr_data != NULL) {
            free(stderr_data);
            stderr_data = NULL;
        }
        if (rc != CMAPER_OK || probe_xml == NULL || probe_xml_size == 0) {
            if (probe_xml != NULL) {
                free(probe_xml);
            }
            cmaper_scan_detail_host_message_setf(host_result, "probe scan failed");
            cmaper_scan_detail_progress_mark_stage(
                progress_state,
                target_index,
                CMAPER_SCAN_DETAIL_STAGE_FAILED
            );
            return;
        }

        host_result->probe_success = true;
        final_xml = probe_xml;
        final_xml_size = probe_xml_size;
        probe_xml = NULL;
        probe_xml_size = 0;

        rc = cmaper_scan_detail_target_extract_probe_ports(
            final_xml,
            final_xml_size,
            target->ip,
            &probe_ports,
            &probe_port_count
        );
        if (rc == CMAPER_OK
            && probe_port_count == 0
            && request->plan != NULL
            && request->plan->sudo) {
            char *connect_probe_xml = NULL;
            size_t connect_probe_xml_size = 0;
            int *connect_probe_ports = NULL;
            size_t connect_probe_port_count = 0;
            cmaper_err_t fallback_rc;

            fallback_rc = cmaper_scan_detail_build_probe_command_with_transport(
                request,
                target,
                CMAPER_SCAN_DETAIL_PROBE_TRANSPORT_TCP_CONNECT,
                &spoof_policy,
                &command
            );
            if (fallback_rc == CMAPER_OK) {
                if (progress_state == NULL || !progress_state->dynamic_render) {
                    cmaper_log(
                        request->logger,
                        CMAPER_LOG_INFO,
                        "scan/detail[%s]: probe fallback command => %s",
                        target->ip,
                        command.rendered
                    );
                }

                fallback_rc = cmaper_scan_detail_run_command(
                    request,
                    &command,
                    "detail-probe-connect",
                    heartbeat_seconds,
                    &connect_probe_xml,
                    &connect_probe_xml_size,
                    &stderr_data,
                    &stderr_size
                );
                if (stderr_data != NULL) {
                    free(stderr_data);
                    stderr_data = NULL;
                }
            }

            if (fallback_rc == CMAPER_OK && connect_probe_xml != NULL && connect_probe_xml_size > 0) {
                fallback_rc = cmaper_scan_detail_target_extract_probe_ports(
                    connect_probe_xml,
                    connect_probe_xml_size,
                    target->ip,
                    &connect_probe_ports,
                    &connect_probe_port_count
                );
                if (fallback_rc == CMAPER_OK) {
                    if (final_xml != NULL) {
                        free(final_xml);
                    }
                    final_xml = connect_probe_xml;
                    final_xml_size = connect_probe_xml_size;
                    connect_probe_xml = NULL;
                    connect_probe_xml_size = 0;

                    if (probe_ports != NULL) {
                        free(probe_ports);
                    }
                    probe_ports = connect_probe_ports;
                    probe_port_count = connect_probe_port_count;
                    connect_probe_ports = NULL;
                    connect_probe_port_count = 0;

                    if (probe_port_count > 0) {
                        cmaper_log(
                            request->logger,
                            CMAPER_LOG_WARN,
                            "scan/detail[%s]: probe fallback (-sT) recovered %zu open tcp ports",
                            target->ip,
                            probe_port_count
                        );
                    }
                }
            }

            if (connect_probe_xml != NULL) {
                free(connect_probe_xml);
            }
            if (connect_probe_ports != NULL) {
                free(connect_probe_ports);
            }
        }

        if (rc != CMAPER_OK) {
            host_result->used_probe_xml_as_final = true;
            host_result->success = true;
            cmaper_scan_detail_host_message_setf(
                host_result,
                "probe xml parse failed, using probe xml as final"
            );
        } else if (probe_port_count > 0) {
            char *enrichment_xml = NULL;
            size_t enrichment_xml_size = 0;

            cmaper_scan_detail_progress_set_open_ports(
                progress_state,
                target_index,
                probe_port_count
            );

            host_result->enrichment_attempted = true;
            cmaper_scan_detail_progress_mark_stage(
                progress_state,
                target_index,
                CMAPER_SCAN_DETAIL_STAGE_ENRICHMENT
            );

            rc = cmaper_scan_detail_build_enrichment_like_command(
                request,
                target->ip,
                probe_ports,
                probe_port_count,
                &spoof_policy,
                &command
            );
            if (rc == CMAPER_OK) {
                if (progress_state == NULL || !progress_state->dynamic_render) {
                    cmaper_log(
                        request->logger,
                        CMAPER_LOG_INFO,
                        "scan/detail[%s]: enrichment command => %s",
                        target->ip,
                        command.rendered
                    );
                }

                rc = cmaper_scan_detail_run_command(
                    request,
                    &command,
                    "detail-enrichment",
                    heartbeat_seconds,
                    &enrichment_xml,
                    &enrichment_xml_size,
                    &stderr_data,
                    &stderr_size
                );
                if (stderr_data != NULL) {
                    free(stderr_data);
                    stderr_data = NULL;
                }
            }

            if (rc == CMAPER_OK && enrichment_xml != NULL && enrichment_xml_size > 0) {
                host_result->enrichment_success = true;
                if (final_xml != NULL) {
                    free(final_xml);
                }
                final_xml = enrichment_xml;
                final_xml_size = enrichment_xml_size;
                enrichment_xml = NULL;
                enrichment_xml_size = 0;
            } else {
                if (enrichment_xml != NULL) {
                    free(enrichment_xml);
                }
                host_result->used_probe_xml_as_final = true;
                host_result->success = true;
                cmaper_scan_detail_host_message_setf(
                    host_result,
                    "enrichment failed, probe xml kept as final"
                );
            }
        } else {
            cmaper_scan_detail_progress_set_open_ports(
                progress_state,
                target_index,
                0
            );
            host_result->success = true;
            cmaper_scan_detail_host_message_setf(
                host_result,
                "probe completed with no open tcp ports"
            );
        }

        if (probe_ports != NULL) {
            free(probe_ports);
        }

        if (!host_result->success && final_xml != NULL) {
            host_result->success = true;
        }
    }

    if (host_result->success && final_xml != NULL && final_xml_size > 0) {
        if (cmaper_scan_detail_target_count_scripts(
                final_xml,
                final_xml_size,
                target->ip,
                &scripts_count)) {
            cmaper_scan_detail_progress_set_scripts(
                progress_state,
                target_index,
                scripts_count
            );
        }

        rc = cmaper_scan_detail_save_final_xml(
            request,
            target->ip,
            final_xml,
            final_xml_size,
            host_result
        );
        if (rc != CMAPER_OK) {
            cmaper_scan_detail_host_message_setf(host_result, "final xml save failed");
            host_result->success = false;
        }
    }

    if (host_result->success) {
        if (host_result->used_probe_xml_as_final
            || (host_result->enrichment_attempted && !host_result->enrichment_success)) {
            cmaper_scan_detail_progress_mark_stage(
                progress_state,
                target_index,
                CMAPER_SCAN_DETAIL_STAGE_DEGRADED
            );
        } else {
            cmaper_scan_detail_progress_mark_stage(
                progress_state,
                target_index,
                CMAPER_SCAN_DETAIL_STAGE_DONE
            );
        }
    } else {
        cmaper_scan_detail_progress_mark_stage(
            progress_state,
            target_index,
            CMAPER_SCAN_DETAIL_STAGE_FAILED
        );
    }

    if (final_xml != NULL) {
        free(final_xml);
    }
}
