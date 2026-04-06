#include "cmaper/scan/command.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define CMAPER_SCAN_SUDO_BIN "/usr/bin/sudo"

static cmaper_err_t cmaper_scan_command_push_arg(
    cmaper_scan_command_t *command,
    const char *value,
    cmaper_scan_command_diag_t *diag
) {
    int written;

    if (command == NULL || value == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    if (command->argc >= CMAPER_SCAN_COMMAND_MAX_ARGS) {
        cmaper_scan_command_diag_setf(
            diag,
            "argv",
            "nmap command exceeded internal argument limit (%d)",
            CMAPER_SCAN_COMMAND_MAX_ARGS
        );
        return CMAPER_ERR_IO;
    }

    written = snprintf(
        command->arg_data[command->argc],
        sizeof(command->arg_data[command->argc]),
        "%s",
        value
    );
    if (written < 0 || written >= (int) sizeof(command->arg_data[command->argc])) {
        cmaper_scan_command_diag_setf(diag, "argv", "nmap argument is too long");
        return CMAPER_ERR_IO;
    }

    command->argv[command->argc] = command->arg_data[command->argc];
    command->argc += 1;
    command->argv[command->argc] = NULL;

    return CMAPER_OK;
}

static void cmaper_scan_command_finalize_render(cmaper_scan_command_t *command) {
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

void cmaper_scan_command_diag_clear(cmaper_scan_command_diag_t *diag) {
    if (diag == NULL) {
        return;
    }

    diag->field = NULL;
    diag->message[0] = '\0';
}

void cmaper_scan_command_diag_setf(
    cmaper_scan_command_diag_t *diag,
    const char *field,
    const char *fmt,
    ...
) {
    va_list args;

    cmaper_scan_command_diag_clear(diag);
    if (diag == NULL) {
        return;
    }

    diag->field = field;
    if (fmt == NULL) {
        return;
    }

    va_start(args, fmt);
    vsnprintf(diag->message, sizeof(diag->message), fmt, args);
    va_end(args);
}

void cmaper_scan_discovery_plan_init(cmaper_scan_discovery_plan_t *plan) {
    if (plan == NULL) {
        return;
    }

    plan->target_expression = NULL;
    plan->representative_target[0] = '\0';
    plan->target_is_cidr = false;
    plan->no_ping = false;
    plan->kind = CMAPER_DISCOVERY_KIND_PORT_SCAN;
    plan->transport = CMAPER_DISCOVERY_TRANSPORT_TCP_CONNECT;
    plan->use_exact_ports = false;
    plan->exact_ports = NULL;
    plan->top_ports = 0;
    plan->timing_template = 3;
    plan->spoof_requested = false;
    plan->spoof_applied = false;
    plan->spoof_suppression = CMAPER_SPOOF_SUPPRESS_NONE;
    plan->spoof_value[0] = '\0';
}

void cmaper_scan_command_init(cmaper_scan_command_t *command) {
    size_t i;

    if (command == NULL) {
        return;
    }

    command->argc = 0;
    command->rendered[0] = '\0';
    for (i = 0; i < CMAPER_SCAN_COMMAND_MAX_ARGS; ++i) {
        command->arg_data[i][0] = '\0';
        command->argv[i] = NULL;
    }
    command->argv[CMAPER_SCAN_COMMAND_MAX_ARGS] = NULL;
}

int cmaper_scan_discovery_default_top_ports(cmaper_scan_profile_t profile) {
    switch (profile) {
    case CMAPER_SCAN_PROFILE_LOW:
        return 100;
    case CMAPER_SCAN_PROFILE_MID:
        return 1000;
    case CMAPER_SCAN_PROFILE_HIGH:
        return 1000;
    case CMAPER_SCAN_PROFILE_UNSET:
        break;
    }

    return 1000;
}

cmaper_err_t cmaper_scan_discovery_plan_build(
    const cmaper_scan_plan_t *scan_plan,
    const cmaper_scan_source_identity_t *identity,
    cmaper_scan_discovery_plan_t *discovery_plan,
    cmaper_scan_command_diag_t *diag
) {
    if (scan_plan == NULL || identity == NULL || discovery_plan == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    cmaper_scan_command_diag_clear(diag);
    cmaper_scan_discovery_plan_init(discovery_plan);

    discovery_plan->target_expression = scan_plan->target;
    discovery_plan->target_is_cidr = identity->representative_is_cidr;
    discovery_plan->no_ping = scan_plan->no_ping;
    discovery_plan->transport = scan_plan->sudo
        ? CMAPER_DISCOVERY_TRANSPORT_SYN
        : CMAPER_DISCOVERY_TRANSPORT_TCP_CONNECT;
    discovery_plan->use_exact_ports = scan_plan->exact_ports != NULL;
    discovery_plan->exact_ports = scan_plan->exact_ports;
    discovery_plan->top_ports = cmaper_scan_discovery_default_top_ports(scan_plan->profile);
    discovery_plan->timing_template = scan_plan->timing_template;
    discovery_plan->spoof_requested = scan_plan->spoof_mac_mode != CMAPER_SCAN_SPOOF_MAC_OFF;

    if (snprintf(discovery_plan->representative_target,
            sizeof(discovery_plan->representative_target),
            "%s",
            identity->representative_target) >= (int) sizeof(discovery_plan->representative_target)) {
        cmaper_scan_command_diag_setf(
            diag,
            "target",
            "representative target exceeds internal buffer limit"
        );
        return CMAPER_ERR_IO;
    }

    if (discovery_plan->target_is_cidr
        && !discovery_plan->no_ping
        && !discovery_plan->use_exact_ports) {
        discovery_plan->kind = CMAPER_DISCOVERY_KIND_HOST_DISCOVERY;
    } else {
        discovery_plan->kind = CMAPER_DISCOVERY_KIND_PORT_SCAN;
    }

    if (!discovery_plan->spoof_requested) {
        discovery_plan->spoof_suppression = CMAPER_SPOOF_SUPPRESS_DISABLED;
        return CMAPER_OK;
    }

    (void) identity;
    discovery_plan->spoof_suppression = CMAPER_SPOOF_SUPPRESS_DISCOVERY_PHASE;

    return CMAPER_OK;
}

cmaper_err_t cmaper_scan_command_build_discovery(
    const cmaper_runtime_paths_t *paths,
    const cmaper_scan_discovery_plan_t *discovery_plan,
    cmaper_scan_command_t *command,
    cmaper_scan_command_diag_t *diag
) {
    char timing_arg[16];
    char top_ports_arg[16];
    cmaper_err_t rc;

    if (paths == NULL || discovery_plan == NULL || command == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    cmaper_scan_command_diag_clear(diag);
    cmaper_scan_command_init(command);

    if (discovery_plan->transport == CMAPER_DISCOVERY_TRANSPORT_SYN) {
        rc = cmaper_scan_command_push_arg(command, CMAPER_SCAN_SUDO_BIN, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    rc = cmaper_scan_command_push_arg(
        command,
        paths->nmap_bin[0] != '\0' ? paths->nmap_bin : "nmap",
        diag
    );
    if (rc != CMAPER_OK) {
        return rc;
    }

    rc = cmaper_scan_command_push_arg(command, "-n", diag);
    if (rc != CMAPER_OK) {
        return rc;
    }

    rc = cmaper_scan_command_push_arg(command, "-oX", diag);
    if (rc != CMAPER_OK) {
        return rc;
    }

    rc = cmaper_scan_command_push_arg(command, "-", diag);
    if (rc != CMAPER_OK) {
        return rc;
    }

    if (discovery_plan->kind == CMAPER_DISCOVERY_KIND_HOST_DISCOVERY) {
        rc = cmaper_scan_command_push_arg(command, "-sn", diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
    } else {
        rc = cmaper_scan_command_push_arg(
            command,
            discovery_plan->transport == CMAPER_DISCOVERY_TRANSPORT_SYN ? "-sS" : "-sT",
            diag
        );
        if (rc != CMAPER_OK) {
            return rc;
        }

        if (discovery_plan->use_exact_ports) {
            rc = cmaper_scan_command_push_arg(command, "-p", diag);
            if (rc != CMAPER_OK) {
                return rc;
            }
            rc = cmaper_scan_command_push_arg(command, discovery_plan->exact_ports, diag);
            if (rc != CMAPER_OK) {
                return rc;
            }
        } else {
            rc = cmaper_scan_command_push_arg(command, "--top-ports", diag);
            if (rc != CMAPER_OK) {
                return rc;
            }

            snprintf(top_ports_arg, sizeof(top_ports_arg), "%d", discovery_plan->top_ports);
            rc = cmaper_scan_command_push_arg(command, top_ports_arg, diag);
            if (rc != CMAPER_OK) {
                return rc;
            }
        }

        if (discovery_plan->no_ping) {
            rc = cmaper_scan_command_push_arg(command, "-Pn", diag);
            if (rc != CMAPER_OK) {
                return rc;
            }
        }
    }

    snprintf(timing_arg, sizeof(timing_arg), "-T%d", discovery_plan->timing_template);
    rc = cmaper_scan_command_push_arg(command, timing_arg, diag);
    if (rc != CMAPER_OK) {
        return rc;
    }

    if (discovery_plan->spoof_applied) {
        rc = cmaper_scan_command_push_arg(command, "--spoof-mac", diag);
        if (rc != CMAPER_OK) {
            return rc;
        }

        rc = cmaper_scan_command_push_arg(command, discovery_plan->spoof_value, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    rc = cmaper_scan_command_push_arg(command, discovery_plan->target_expression, diag);
    if (rc != CMAPER_OK) {
        return rc;
    }

    cmaper_scan_command_finalize_render(command);
    return CMAPER_OK;
}

void cmaper_scan_command_render(FILE *stream, const cmaper_scan_command_t *command) {
    if (stream == NULL || command == NULL) {
        return;
    }

    fprintf(stream, "%s\n", command->rendered);
}

const char *cmaper_discovery_kind_name(cmaper_discovery_kind_t kind) {
    switch (kind) {
    case CMAPER_DISCOVERY_KIND_HOST_DISCOVERY:
        return "host-discovery";
    case CMAPER_DISCOVERY_KIND_PORT_SCAN:
        break;
    }

    return "port-scan";
}

const char *cmaper_discovery_transport_name(cmaper_discovery_transport_t transport) {
    switch (transport) {
    case CMAPER_DISCOVERY_TRANSPORT_SYN:
        return "syn";
    case CMAPER_DISCOVERY_TRANSPORT_TCP_CONNECT:
        break;
    }

    return "tcp-connect";
}

const char *cmaper_spoof_suppression_name(cmaper_spoof_suppression_t suppression) {
    switch (suppression) {
    case CMAPER_SPOOF_SUPPRESS_DISABLED:
        return "disabled";
    case CMAPER_SPOOF_SUPPRESS_UNPRIVILEGED:
        return "unprivileged";
    case CMAPER_SPOOF_SUPPRESS_LOOPBACK:
        return "loopback";
    case CMAPER_SPOOF_SUPPRESS_DISCOVERY_PHASE:
        return "discovery-phase";
    case CMAPER_SPOOF_SUPPRESS_NONE:
        break;
    }

    return "none";
}
