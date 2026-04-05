#include "cmaper/scan/detail.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmaper/scan/command.h"
#include "cmaper/scan/nmap_xml_parse.h"
#include "cmaper/scan/nmap_xml_utils.h"

#define CMAPER_SCAN_DETAIL_CMD_MAX_ARGS 48
#define CMAPER_SCAN_DETAIL_CMD_ARG_CAP 256
#define CMAPER_SCAN_DETAIL_CMD_RENDER_CAP 2048

typedef struct {
    int argc;
    char args[CMAPER_SCAN_DETAIL_CMD_MAX_ARGS][CMAPER_SCAN_DETAIL_CMD_ARG_CAP];
    const char *argv[CMAPER_SCAN_DETAIL_CMD_MAX_ARGS + 1];
    char rendered[CMAPER_SCAN_DETAIL_CMD_RENDER_CAP];
} cmaper_scan_detail_command_t;

typedef struct {
    const cmaper_scan_detail_request_t *request;
    cmaper_scan_detail_result_t *result;
    size_t next_index;
    pthread_mutex_t index_lock;
} cmaper_scan_detail_pool_t;

typedef struct {
    bool enabled;
    cmaper_spoof_suppression_t suppression;
    char value[32];
} cmaper_scan_detail_spoof_policy_t;

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

static void cmaper_scan_detail_command_init(cmaper_scan_detail_command_t *command) {
    size_t i;

    if (command == NULL) {
        return;
    }

    command->argc = 0;
    command->rendered[0] = '\0';
    for (i = 0; i < CMAPER_SCAN_DETAIL_CMD_MAX_ARGS; ++i) {
        command->args[i][0] = '\0';
        command->argv[i] = NULL;
    }
    command->argv[CMAPER_SCAN_DETAIL_CMD_MAX_ARGS] = NULL;
}

static cmaper_err_t cmaper_scan_detail_command_push(
    cmaper_scan_detail_command_t *command,
    const char *value
) {
    int written;

    if (command == NULL || value == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    if (command->argc >= CMAPER_SCAN_DETAIL_CMD_MAX_ARGS) {
        return CMAPER_ERR_IO;
    }

    written = snprintf(
        command->args[command->argc],
        sizeof(command->args[command->argc]),
        "%s",
        value
    );
    if (written < 0 || written >= (int) sizeof(command->args[command->argc])) {
        return CMAPER_ERR_IO;
    }

    command->argv[command->argc] = command->args[command->argc];
    command->argc += 1;
    command->argv[command->argc] = NULL;
    return CMAPER_OK;
}

static void cmaper_scan_detail_command_finalize(cmaper_scan_detail_command_t *command) {
    size_t i;
    size_t offset = 0;

    if (command == NULL) {
        return;
    }

    command->rendered[0] = '\0';
    for (i = 0; i < (size_t) command->argc; ++i) {
        int written;
        const char *prefix = i == 0 ? "" : " ";

        written = snprintf(
            command->rendered + offset,
            sizeof(command->rendered) - offset,
            "%s%s",
            prefix,
            command->argv[i]
        );
        if (written < 0 || (size_t) written >= (sizeof(command->rendered) - offset)) {
            command->rendered[sizeof(command->rendered) - 1] = '\0';
            return;
        }
        offset += (size_t) written;
    }
}

static cmaper_err_t cmaper_scan_detail_ports_to_csv(
    const int *ports,
    size_t port_count,
    char *out,
    size_t out_cap
) {
    size_t i;
    size_t offset = 0;

    if (ports == NULL || port_count == 0 || out == NULL || out_cap == 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    out[0] = '\0';
    for (i = 0; i < port_count; ++i) {
        int written = snprintf(
            out + offset,
            out_cap - offset,
            "%s%d",
            i == 0 ? "" : ",",
            ports[i]
        );
        if (written < 0 || (size_t) written >= (out_cap - offset)) {
            return CMAPER_ERR_IO;
        }
        offset += (size_t) written;
    }

    return CMAPER_OK;
}

static void cmaper_scan_detail_spoof_policy_resolve(
    const cmaper_scan_plan_t *plan,
    const cmaper_scan_source_identity_t *source_identity,
    cmaper_scan_detail_spoof_policy_t *policy
) {
    if (policy == NULL) {
        return;
    }

    policy->enabled = false;
    policy->suppression = CMAPER_SPOOF_SUPPRESS_DISABLED;
    policy->value[0] = '\0';

    if (plan == NULL || source_identity == NULL) {
        return;
    }

    if (plan->spoof_mac_mode == CMAPER_SCAN_SPOOF_MAC_OFF) {
        policy->suppression = CMAPER_SPOOF_SUPPRESS_DISABLED;
        return;
    }

    if (!plan->sudo) {
        policy->suppression = CMAPER_SPOOF_SUPPRESS_UNPRIVILEGED;
        return;
    }

    if (source_identity->representative_is_loopback) {
        policy->suppression = CMAPER_SPOOF_SUPPRESS_LOOPBACK;
        return;
    }

    policy->enabled = true;
    policy->suppression = CMAPER_SPOOF_SUPPRESS_NONE;
    if (source_identity->has_spoofed_mac) {
        snprintf(policy->value, sizeof(policy->value), "%s", source_identity->spoofed_mac);
    }
}

static cmaper_err_t cmaper_scan_detail_command_add_base(
    const cmaper_scan_detail_request_t *request,
    cmaper_scan_detail_command_t *command
) {
    cmaper_err_t rc;

    rc = cmaper_scan_detail_command_push(
        command,
        request->paths->nmap_bin[0] != '\0' ? request->paths->nmap_bin : "nmap"
    );
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_scan_detail_command_push(command, "-n");
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_scan_detail_command_push(command, "-oX");
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_scan_detail_command_push(command, "-");
    if (rc != CMAPER_OK) {
        return rc;
    }

    return CMAPER_OK;
}

static cmaper_err_t cmaper_scan_detail_command_add_transport(
    const cmaper_scan_plan_t *plan,
    cmaper_scan_detail_command_t *command
) {
    return cmaper_scan_detail_command_push(command, plan->sudo ? "-sS" : "-sT");
}

static cmaper_err_t cmaper_scan_detail_command_add_timing(
    const cmaper_scan_plan_t *plan,
    cmaper_scan_detail_command_t *command
) {
    char timing_arg[16];

    snprintf(timing_arg, sizeof(timing_arg), "-T%d", plan->timing_template);
    return cmaper_scan_detail_command_push(command, timing_arg);
}

static cmaper_err_t cmaper_scan_detail_command_add_spoof(
    const cmaper_scan_detail_spoof_policy_t *spoof_policy,
    cmaper_scan_detail_command_t *command
) {
    cmaper_err_t rc;

    if (spoof_policy == NULL || !spoof_policy->enabled) {
        return CMAPER_OK;
    }

    if (spoof_policy->value[0] == '\0') {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = cmaper_scan_detail_command_push(command, "--spoof-mac");
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_scan_detail_command_push(command, spoof_policy->value);
    if (rc != CMAPER_OK) {
        return rc;
    }
    return CMAPER_OK;
}

static cmaper_err_t cmaper_scan_detail_build_probe_command(
    const cmaper_scan_detail_request_t *request,
    const cmaper_scan_detail_target_t *target,
    const cmaper_scan_detail_spoof_policy_t *spoof_policy,
    cmaper_scan_detail_command_t *command
) {
    cmaper_err_t rc;
    char top_ports[16];
    int probe_top_ports;

    cmaper_scan_detail_command_init(command);

    rc = cmaper_scan_detail_command_add_base(request, command);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_scan_detail_command_add_transport(request->plan, command);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_scan_detail_command_push(command, "--top-ports");
    if (rc != CMAPER_OK) {
        return rc;
    }

    probe_top_ports = cmaper_scan_discovery_default_top_ports(request->plan->profile);
    snprintf(top_ports, sizeof(top_ports), "%d", probe_top_ports);
    rc = cmaper_scan_detail_command_push(command, top_ports);
    if (rc != CMAPER_OK) {
        return rc;
    }

    rc = cmaper_scan_detail_command_push(command, "-Pn");
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_scan_detail_command_add_timing(request->plan, command);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_scan_detail_command_add_spoof(spoof_policy, command);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_scan_detail_command_push(command, target->ip);
    if (rc != CMAPER_OK) {
        return rc;
    }

    cmaper_scan_detail_command_finalize(command);
    return CMAPER_OK;
}

static cmaper_err_t cmaper_scan_detail_build_enrichment_like_command(
    const cmaper_scan_detail_request_t *request,
    const char *ip,
    const int *ports,
    size_t port_count,
    const cmaper_scan_detail_spoof_policy_t *spoof_policy,
    cmaper_scan_detail_command_t *command
) {
    cmaper_err_t rc;
    char ports_csv[512];

    if (ip == NULL || ports == NULL || port_count == 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = cmaper_scan_detail_ports_to_csv(ports, port_count, ports_csv, sizeof(ports_csv));
    if (rc != CMAPER_OK) {
        return rc;
    }

    cmaper_scan_detail_command_init(command);

    rc = cmaper_scan_detail_command_add_base(request, command);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_scan_detail_command_add_transport(request->plan, command);
    if (rc != CMAPER_OK) {
        return rc;
    }

    rc = cmaper_scan_detail_command_push(command, "-p");
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_scan_detail_command_push(command, ports_csv);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_scan_detail_command_push(command, "-Pn");
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_scan_detail_command_add_timing(request->plan, command);
    if (rc != CMAPER_OK) {
        return rc;
    }

    if (request->plan->service_detection) {
        rc = cmaper_scan_detail_command_push(command, "-sV");
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_scan_detail_command_push(command, "-sC");
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    if (request->plan->os_detection) {
        rc = cmaper_scan_detail_command_push(command, "-O");
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    if (request->plan->traceroute) {
        rc = cmaper_scan_detail_command_push(command, "--traceroute");
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    rc = cmaper_scan_detail_command_add_spoof(spoof_policy, command);
    if (rc != CMAPER_OK) {
        return rc;
    }

    rc = cmaper_scan_detail_command_push(command, ip);
    if (rc != CMAPER_OK) {
        return rc;
    }

    cmaper_scan_detail_command_finalize(command);
    return CMAPER_OK;
}

static cmaper_err_t cmaper_scan_detail_run_command(
    const cmaper_scan_detail_request_t *request,
    const cmaper_scan_detail_command_t *command,
    const char *phase_label,
    char **out_stdout_data,
    size_t *out_stdout_size,
    char **out_stderr_data,
    size_t *out_stderr_size
) {
    cmaper_scan_process_request_t process_request;
    cmaper_scan_process_result_t process_result;
    cmaper_scan_process_run_fn backend;
    cmaper_err_t rc;

    if (request == NULL || command == NULL || out_stdout_data == NULL || out_stdout_size == NULL
        || out_stderr_data == NULL || out_stderr_size == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    *out_stdout_data = NULL;
    *out_stdout_size = 0;
    *out_stderr_data = NULL;
    *out_stderr_size = 0;

    backend = request->process_backend != NULL ? request->process_backend : cmaper_scan_process_run;

    process_request.program_path = command->argv[0];
    process_request.argv = command->argv;
    process_request.heartbeat_seconds = 15;
    process_request.heartbeat_label = phase_label;

    cmaper_scan_process_result_init(&process_result);
    rc = backend(&process_request, request->logger, &process_result);
    if (rc != CMAPER_OK) {
        return rc;
    }

    if (process_result.exit_code != 0) {
        cmaper_log(
            request->logger,
            CMAPER_LOG_WARN,
            "scan/detail: %s exited with code %d",
            phase_label,
            process_result.exit_code
        );
        if (process_result.stderr_data != NULL && process_result.stderr_data[0] != '\0') {
            cmaper_log(
                request->logger,
                CMAPER_LOG_WARN,
                "scan/detail: %s stderr => %.256s",
                phase_label,
                process_result.stderr_data
            );
        }
        cmaper_scan_process_result_dispose(&process_result);
        return CMAPER_ERR_INTERNAL;
    }

    *out_stdout_data = process_result.stdout_data;
    *out_stdout_size = process_result.stdout_size;
    process_result.stdout_data = NULL;
    process_result.stdout_size = 0;

    *out_stderr_data = process_result.stderr_data;
    *out_stderr_size = process_result.stderr_size;
    process_result.stderr_data = NULL;
    process_result.stderr_size = 0;

    cmaper_scan_process_result_dispose(&process_result);
    return CMAPER_OK;
}

static cmaper_err_t cmaper_scan_detail_extract_probe_ports(
    const char *probe_xml,
    size_t probe_xml_size,
    const char *target_ip,
    int **out_ports,
    size_t *out_port_count
) {
    cmaper_nmap_xml_document_t document;
    cmaper_nmap_xml_diag_t diag;
    cmaper_err_t rc;
    size_t i;
    const cmaper_nmap_xml_host_t *fallback_up_host = NULL;

    if (probe_xml == NULL || target_ip == NULL || out_ports == NULL || out_port_count == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    *out_ports = NULL;
    *out_port_count = 0;

    cmaper_nmap_xml_document_init(&document);
    cmaper_nmap_xml_diag_clear(&diag);

    rc = cmaper_nmap_xml_parse_memory(probe_xml, probe_xml_size, &document, &diag);
    if (rc != CMAPER_OK) {
        cmaper_nmap_xml_document_dispose(&document);
        return rc;
    }

    for (i = 0; i < document.host_count; ++i) {
        const cmaper_nmap_xml_host_t *host = &document.hosts[i];
        const char *ip = cmaper_nmap_host_primary_ip(host);

        if (host->status.state != NULL && strcmp(host->status.state, "up") == 0 && fallback_up_host == NULL) {
            fallback_up_host = host;
        }

        if (ip != NULL && strcmp(ip, target_ip) == 0) {
            rc = cmaper_nmap_host_open_tcp_ports_sorted(host, out_ports, out_port_count);
            cmaper_nmap_xml_document_dispose(&document);
            return rc;
        }
    }

    if (fallback_up_host != NULL) {
        rc = cmaper_nmap_host_open_tcp_ports_sorted(fallback_up_host, out_ports, out_port_count);
        cmaper_nmap_xml_document_dispose(&document);
        return rc;
    }

    cmaper_nmap_xml_document_dispose(&document);
    return CMAPER_OK;
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

static void cmaper_scan_detail_execute_for_target(
    const cmaper_scan_detail_request_t *request,
    const cmaper_scan_detail_target_t *target,
    cmaper_scan_detail_host_result_t *host_result
) {
    cmaper_scan_detail_spoof_policy_t spoof_policy;
    cmaper_scan_detail_command_t command;
    char *final_xml = NULL;
    size_t final_xml_size = 0;
    char *probe_xml = NULL;
    size_t probe_xml_size = 0;
    char *stderr_data = NULL;
    size_t stderr_size = 0;
    cmaper_err_t rc;

    if (request == NULL || target == NULL || host_result == NULL) {
        return;
    }

    snprintf(host_result->ip, sizeof(host_result->ip), "%s", target->ip);

    cmaper_scan_detail_spoof_policy_resolve(request->plan, request->source_identity, &spoof_policy);

    if (target->has_open_tcp_ports) {
        host_result->direct_scan_attempted = true;

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
            return;
        }

        cmaper_log(
            request->logger,
            CMAPER_LOG_INFO,
            "scan/detail[%s]: direct command => %s",
            target->ip,
            command.rendered
        );

        rc = cmaper_scan_detail_run_command(
            request,
            &command,
            "detail-direct",
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
            return;
        }

        host_result->direct_scan_success = true;
        host_result->success = true;
    } else {
        int *probe_ports = NULL;
        size_t probe_port_count = 0;

        host_result->probe_attempted = true;

        rc = cmaper_scan_detail_build_probe_command(request, target, &spoof_policy, &command);
        if (rc != CMAPER_OK) {
            cmaper_scan_detail_host_message_setf(host_result, "failed to build probe command");
            return;
        }

        cmaper_log(
            request->logger,
            CMAPER_LOG_INFO,
            "scan/detail[%s]: probe command => %s",
            target->ip,
            command.rendered
        );

        rc = cmaper_scan_detail_run_command(
            request,
            &command,
            "detail-probe",
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
            return;
        }

        host_result->probe_success = true;
        final_xml = probe_xml;
        final_xml_size = probe_xml_size;
        probe_xml = NULL;
        probe_xml_size = 0;

        rc = cmaper_scan_detail_extract_probe_ports(
            final_xml,
            final_xml_size,
            target->ip,
            &probe_ports,
            &probe_port_count
        );
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

            host_result->enrichment_attempted = true;

            rc = cmaper_scan_detail_build_enrichment_like_command(
                request,
                target->ip,
                probe_ports,
                probe_port_count,
                &spoof_policy,
                &command
            );
            if (rc == CMAPER_OK) {
                cmaper_log(
                    request->logger,
                    CMAPER_LOG_INFO,
                    "scan/detail[%s]: enrichment command => %s",
                    target->ip,
                    command.rendered
                );

                rc = cmaper_scan_detail_run_command(
                    request,
                    &command,
                    "detail-enrichment",
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
            host_result->used_probe_xml_as_final = true;
            host_result->success = true;
            cmaper_scan_detail_host_message_setf(
                host_result,
                "probe found no open tcp ports, probe xml kept as final"
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

    if (final_xml != NULL) {
        free(final_xml);
    }
}

static void *cmaper_scan_detail_worker_entry(void *arg) {
    cmaper_scan_detail_pool_t *pool = (cmaper_scan_detail_pool_t *) arg;

    while (true) {
        size_t index;
        const cmaper_scan_detail_target_t *target;
        cmaper_scan_detail_host_result_t *host_result;

        pthread_mutex_lock(&pool->index_lock);
        index = pool->next_index;
        if (index < pool->request->targets->count) {
            pool->next_index += 1U;
        }
        pthread_mutex_unlock(&pool->index_lock);

        if (index >= pool->request->targets->count) {
            break;
        }

        target = &pool->request->targets->items[index];
        host_result = &pool->result->hosts[index];
        cmaper_scan_detail_execute_for_target(pool->request, target, host_result);
    }

    return NULL;
}

void cmaper_scan_detail_result_init(cmaper_scan_detail_result_t *result) {
    if (result == NULL) {
        return;
    }

    result->hosts = NULL;
    result->host_count = 0;
    result->successful_hosts = 0;
    result->failed_hosts = 0;
    result->degraded_hosts = 0;
}

void cmaper_scan_detail_result_dispose(cmaper_scan_detail_result_t *result) {
    if (result == NULL) {
        return;
    }

    if (result->hosts != NULL) {
        free(result->hosts);
        result->hosts = NULL;
    }

    result->host_count = 0;
    result->successful_hosts = 0;
    result->failed_hosts = 0;
    result->degraded_hosts = 0;
}

cmaper_err_t cmaper_scan_detail_execute(
    const cmaper_scan_detail_request_t *request,
    cmaper_scan_detail_result_t *result
) {
    pthread_t *threads = NULL;
    size_t thread_count;
    size_t i;
    cmaper_scan_detail_pool_t pool;

    if (request == NULL || request->plan == NULL || request->paths == NULL || request->targets == NULL
        || request->artifact_policy == NULL || request->logger == NULL || result == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    cmaper_scan_detail_result_dispose(result);
    cmaper_scan_detail_result_init(result);

    result->host_count = request->targets->count;
    if (result->host_count == 0) {
        return CMAPER_OK;
    }

    result->hosts = (cmaper_scan_detail_host_result_t *) calloc(
        result->host_count,
        sizeof(cmaper_scan_detail_host_result_t)
    );
    if (result->hosts == NULL) {
        return CMAPER_ERR_OOM;
    }

    thread_count = (size_t) request->worker_limit;
    if (thread_count == 0) {
        thread_count = 1;
    }
    if (thread_count > result->host_count) {
        thread_count = result->host_count;
    }

    threads = (pthread_t *) calloc(thread_count, sizeof(pthread_t));
    if (threads == NULL) {
        cmaper_scan_detail_result_dispose(result);
        cmaper_scan_detail_result_init(result);
        return CMAPER_ERR_OOM;
    }

    pool.request = request;
    pool.result = result;
    pool.next_index = 0;
    if (pthread_mutex_init(&pool.index_lock, NULL) != 0) {
        free(threads);
        cmaper_scan_detail_result_dispose(result);
        cmaper_scan_detail_result_init(result);
        return CMAPER_ERR_INTERNAL;
    }

    for (i = 0; i < thread_count; ++i) {
        if (pthread_create(&threads[i], NULL, cmaper_scan_detail_worker_entry, &pool) != 0) {
            size_t j;

            for (j = 0; j < i; ++j) {
                pthread_join(threads[j], NULL);
            }
            pthread_mutex_destroy(&pool.index_lock);
            free(threads);
            cmaper_scan_detail_result_dispose(result);
            cmaper_scan_detail_result_init(result);
            return CMAPER_ERR_INTERNAL;
        }
    }

    for (i = 0; i < thread_count; ++i) {
        pthread_join(threads[i], NULL);
    }

    pthread_mutex_destroy(&pool.index_lock);
    free(threads);

    for (i = 0; i < result->host_count; ++i) {
        cmaper_scan_detail_host_result_t *host = &result->hosts[i];

        if (host->success) {
            result->successful_hosts += 1U;
            if (host->used_probe_xml_as_final
                || (host->enrichment_attempted && !host->enrichment_success)) {
                result->degraded_hosts += 1U;
                cmaper_log(
                    request->logger,
                    CMAPER_LOG_WARN,
                    "scan/detail[%s]: degraded result (%s)",
                    host->ip[0] != '\0' ? host->ip : "(unknown)",
                    host->message[0] != '\0' ? host->message : "fallback xml used"
                );
            }
        } else {
            result->failed_hosts += 1U;
            cmaper_log(
                request->logger,
                CMAPER_LOG_WARN,
                "scan/detail[%s]: host failed (%s)",
                host->ip[0] != '\0' ? host->ip : "(unknown)",
                host->message[0] != '\0' ? host->message : "no successful xml"
            );
        }
    }

    if (result->failed_hosts > 0) {
        cmaper_log(
            request->logger,
            CMAPER_LOG_WARN,
            "scan/detail: %zu hosts failed, %zu succeeded",
            result->failed_hosts,
            result->successful_hosts
        );
    } else {
        cmaper_log(
            request->logger,
            CMAPER_LOG_OK,
            "scan/detail: all %zu hosts completed successfully",
            result->successful_hosts
        );
    }

    return CMAPER_OK;
}
