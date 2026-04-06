#include "cmaper/scan/internal/detail_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmaper/scan/command.h"
#include "cmaper/scan/script_pipeline.h"

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

void cmaper_scan_detail_spoof_policy_resolve(
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

    if (plan->spoof_mac_mode != CMAPER_SCAN_SPOOF_MAC_CUSTOM) {
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

    if (request->plan->sudo) {
        rc = cmaper_scan_detail_command_push(command, CMAPER_SCAN_SUDO_BIN);
        if (rc != CMAPER_OK) {
            return rc;
        }
        /* Never block detail workers on hidden interactive sudo prompts. */
        rc = cmaper_scan_detail_command_push(command, "-n");
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

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
    if (plan != NULL && plan->sudo) {
        return cmaper_scan_detail_command_push(command, "-sS");
    }
    return cmaper_scan_detail_command_push(command, "-sT");
}

static cmaper_err_t cmaper_scan_detail_command_add_probe_transport(
    const cmaper_scan_plan_t *plan,
    cmaper_scan_detail_probe_transport_t transport,
    cmaper_scan_detail_command_t *command
) {
    if (transport == CMAPER_SCAN_DETAIL_PROBE_TRANSPORT_TCP_CONNECT) {
        return cmaper_scan_detail_command_push(command, "-sT");
    }
    return cmaper_scan_detail_command_add_transport(plan, command);
}

static cmaper_err_t cmaper_scan_detail_command_add_timing(
    int timing_template,
    cmaper_scan_detail_command_t *command
) {
    char timing_arg[16];

    snprintf(timing_arg, sizeof(timing_arg), "-T%d", timing_template);
    return cmaper_scan_detail_command_push(command, timing_arg);
}

static int cmaper_scan_detail_probe_timeout_seconds(cmaper_scan_profile_t profile) {
    switch (profile) {
    case CMAPER_SCAN_PROFILE_LOW:
        return 120;
    case CMAPER_SCAN_PROFILE_MID:
        return 240;
    case CMAPER_SCAN_PROFILE_HIGH:
        return 420;
    case CMAPER_SCAN_PROFILE_UNSET:
        break;
    }

    return 240;
}

static int cmaper_scan_detail_enrichment_timeout_seconds(cmaper_scan_profile_t profile) {
    switch (profile) {
    case CMAPER_SCAN_PROFILE_LOW:
        return 180;
    case CMAPER_SCAN_PROFILE_MID:
        return 360;
    case CMAPER_SCAN_PROFILE_HIGH:
        return 600;
    case CMAPER_SCAN_PROFILE_UNSET:
        break;
    }

    return 360;
}

static int cmaper_scan_detail_probe_max_retries(cmaper_scan_profile_t profile) {
    switch (profile) {
    case CMAPER_SCAN_PROFILE_LOW:
        return 1;
    case CMAPER_SCAN_PROFILE_MID:
        return 2;
    case CMAPER_SCAN_PROFILE_HIGH:
        return 3;
    case CMAPER_SCAN_PROFILE_UNSET:
        break;
    }

    return 2;
}

static cmaper_err_t cmaper_scan_detail_command_add_host_timeout(
    int timeout_seconds,
    cmaper_scan_detail_command_t *command
) {
    cmaper_err_t rc;
    char timeout_value[16];

    if (timeout_seconds <= 0) {
        return CMAPER_OK;
    }

    rc = cmaper_scan_detail_command_push(command, "--host-timeout");
    if (rc != CMAPER_OK) {
        return rc;
    }

    snprintf(timeout_value, sizeof(timeout_value), "%ds", timeout_seconds);
    return cmaper_scan_detail_command_push(command, timeout_value);
}

static cmaper_err_t cmaper_scan_detail_command_add_max_retries(
    int max_retries,
    cmaper_scan_detail_command_t *command
) {
    cmaper_err_t rc;
    char retries_value[16];

    if (max_retries < 0) {
        return CMAPER_OK;
    }

    rc = cmaper_scan_detail_command_push(command, "--max-retries");
    if (rc != CMAPER_OK) {
        return rc;
    }

    snprintf(retries_value, sizeof(retries_value), "%d", max_retries);
    return cmaper_scan_detail_command_push(command, retries_value);
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

static cmaper_err_t cmaper_scan_detail_command_add_script_pipeline(
    cmaper_scan_detail_command_t *command
) {
    const cmaper_scan_script_set_info_t *script_set;
    cmaper_err_t rc;

    script_set = cmaper_scan_script_set_info(CMAPER_SCAN_SCRIPT_SET_NMAP_DEFAULT);
    if (script_set == NULL) {
        return CMAPER_ERR_INTERNAL;
    }

    if (script_set->script_expression == NULL || script_set->script_expression[0] == '\0') {
        return cmaper_scan_detail_command_push(command, "-sC");
    }

    rc = cmaper_scan_detail_command_push(command, "--script");
    if (rc != CMAPER_OK) {
        return rc;
    }

    return cmaper_scan_detail_command_push(command, script_set->script_expression);
}

cmaper_err_t cmaper_scan_detail_build_probe_command(
    const cmaper_scan_detail_request_t *request,
    const cmaper_scan_detail_target_t *target,
    const cmaper_scan_detail_spoof_policy_t *spoof_policy,
    cmaper_scan_detail_command_t *command
) {
    return cmaper_scan_detail_build_probe_command_with_transport(
        request,
        target,
        CMAPER_SCAN_DETAIL_PROBE_TRANSPORT_DEFAULT,
        spoof_policy,
        command
    );
}

cmaper_err_t cmaper_scan_detail_build_probe_command_with_transport(
    const cmaper_scan_detail_request_t *request,
    const cmaper_scan_detail_target_t *target,
    cmaper_scan_detail_probe_transport_t transport,
    const cmaper_scan_detail_spoof_policy_t *spoof_policy,
    cmaper_scan_detail_command_t *command
) {
    cmaper_err_t rc;
    int probe_timing;
    char top_ports[16];
    int probe_top_ports;

    cmaper_scan_detail_command_init(command);

    rc = cmaper_scan_detail_command_add_base(request, command);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_scan_detail_command_add_probe_transport(request->plan, transport, command);
    if (rc != CMAPER_OK) {
        return rc;
    }

    if (request->plan->all_ports) {
        rc = cmaper_scan_detail_command_push(command, "-p-");
        if (rc != CMAPER_OK) {
            return rc;
        }
    } else {
        rc = cmaper_scan_detail_command_push(command, "--top-ports");
        if (rc != CMAPER_OK) {
            return rc;
        }

        probe_top_ports = cmaper_scan_discovery_default_top_ports(request->plan->profile);
        /* Keep probe broad enough to avoid false "no-open-ports" on common services. */
        if (request->plan->profile == CMAPER_SCAN_PROFILE_HIGH && probe_top_ports < 3000) {
            probe_top_ports = 3000;
        } else if (probe_top_ports < 1000) {
            probe_top_ports = 1000;
        }
        snprintf(top_ports, sizeof(top_ports), "%d", probe_top_ports);
        rc = cmaper_scan_detail_command_push(command, top_ports);
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    rc = cmaper_scan_detail_command_push(command, "-Pn");
    if (rc != CMAPER_OK) {
        return rc;
    }
    probe_timing = request->plan->timing_template;
    if (request->plan->profile == CMAPER_SCAN_PROFILE_HIGH && probe_timing > 3) {
        probe_timing = 3;
    }
    rc = cmaper_scan_detail_command_add_timing(probe_timing, command);
    if (rc != CMAPER_OK) {
        return rc;
    }
    /* Bound per-host probe runtime to avoid practically unbounded scans on filtered networks. */
    rc = cmaper_scan_detail_command_add_max_retries(
        cmaper_scan_detail_probe_max_retries(request->plan->profile),
        command
    );
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_scan_detail_command_add_host_timeout(
        cmaper_scan_detail_probe_timeout_seconds(request->plan->profile),
        command
    );
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

cmaper_err_t cmaper_scan_detail_build_enrichment_like_command(
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
    rc = cmaper_scan_detail_command_add_timing(request->plan->timing_template, command);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_scan_detail_command_add_host_timeout(
        cmaper_scan_detail_enrichment_timeout_seconds(request->plan->profile),
        command
    );
    if (rc != CMAPER_OK) {
        return rc;
    }

    if (request->plan->service_detection) {
        rc = cmaper_scan_detail_command_push(command, "-sV");
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_scan_detail_command_add_script_pipeline(command);
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
