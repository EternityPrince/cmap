#include "cmaper/scan/plan.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static const char *cmaper_scan_bool_word(bool value) {
    return value ? "on" : "off";
}

static const char *cmaper_scan_spoof_mode_name(cmaper_scan_spoof_mac_mode_t mode) {
    switch (mode) {
    case CMAPER_SCAN_SPOOF_MAC_OFF:
        return "off";
    case CMAPER_SCAN_SPOOF_MAC_RANDOM:
        return "random";
    case CMAPER_SCAN_SPOOF_MAC_CUSTOM:
        return "custom";
    }

    return "off";
}

static void cmaper_scan_plan_apply_toggle(bool *target, cmaper_scan_toggle_t toggle) {
    if (target == NULL) {
        return;
    }

    if (toggle == CMAPER_SCAN_TOGGLE_ENABLE) {
        *target = true;
    } else if (toggle == CMAPER_SCAN_TOGGLE_DISABLE) {
        *target = false;
    }
}

static void cmaper_scan_plan_apply_overrides(
    cmaper_scan_plan_t *plan,
    const cmaper_scan_options_t *options
) {
    if (options->exact_ports != NULL) {
        plan->exact_ports = options->exact_ports;
    }

    cmaper_scan_plan_apply_toggle(&plan->all_ports, options->all_ports);
    cmaper_scan_plan_apply_toggle(&plan->no_ping, options->no_ping);

    if (options->has_timing_template) {
        plan->timing_template = options->timing_template;
    }

    if (options->has_detail_workers) {
        plan->detail_workers = options->detail_workers;
    }

    cmaper_scan_plan_apply_toggle(&plan->service_detection, options->service_detection);
    cmaper_scan_plan_apply_toggle(&plan->os_detection, options->os_detection);
    cmaper_scan_plan_apply_toggle(&plan->sudo, options->sudo);
    cmaper_scan_plan_apply_toggle(&plan->traceroute, options->traceroute);
    cmaper_scan_plan_apply_toggle(&plan->udp_enrichment, options->udp_enrichment);

    if (options->spoof_mac == CMAPER_SCAN_TOGGLE_DISABLE) {
        plan->spoof_mac_mode = CMAPER_SCAN_SPOOF_MAC_OFF;
        plan->spoof_mac_value = NULL;
    } else if (options->spoof_mac == CMAPER_SCAN_TOGGLE_ENABLE) {
        if (options->spoof_mac_value == NULL || strcmp(options->spoof_mac_value, "random") == 0) {
            plan->spoof_mac_mode = CMAPER_SCAN_SPOOF_MAC_RANDOM;
            plan->spoof_mac_value = NULL;
        } else {
            plan->spoof_mac_mode = CMAPER_SCAN_SPOOF_MAC_CUSTOM;
            plan->spoof_mac_value = options->spoof_mac_value;
        }
    }
}

void cmaper_scan_plan_diag_clear(cmaper_scan_plan_diag_t *diag) {
    if (diag == NULL) {
        return;
    }

    diag->field = NULL;
    diag->message[0] = '\0';
}

void cmaper_scan_plan_diag_setf(
    cmaper_scan_plan_diag_t *diag,
    const char *field,
    const char *fmt,
    ...
) {
    va_list args;

    cmaper_scan_plan_diag_clear(diag);
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

void cmaper_scan_plan_init(cmaper_scan_plan_t *plan) {
    if (plan == NULL) {
        return;
    }

    plan->target = NULL;
    plan->profile = CMAPER_SCAN_PROFILE_UNSET;
    plan->exact_ports = NULL;
    plan->all_ports = false;
    plan->no_ping = false;
    plan->timing_template = 0;
    plan->detail_workers = 0;
    plan->service_detection = false;
    plan->os_detection = false;
    plan->sudo = false;
    plan->spoof_mac_mode = CMAPER_SCAN_SPOOF_MAC_OFF;
    plan->spoof_mac_value = NULL;
    plan->traceroute = false;
    plan->udp_enrichment = false;

    plan->capabilities.exact_ports = false;
    plan->capabilities.all_ports = false;
    plan->capabilities.no_ping = false;
    plan->capabilities.service_detection = false;
    plan->capabilities.os_detection = false;
    plan->capabilities.spoof_mac = false;
    plan->capabilities.traceroute = false;
    plan->capabilities.udp_enrichment = false;
    plan->capabilities.privileged_required = false;
}

void cmaper_scan_plan_apply_defaults(cmaper_scan_plan_t *plan) {
    if (plan == NULL) {
        return;
    }

    if (plan->profile == CMAPER_SCAN_PROFILE_UNSET) {
        plan->profile = CMAPER_SCAN_PROFILE_MID;
    }

    plan->timing_template = 3;
    plan->detail_workers = 16;
    plan->all_ports = false;
    plan->no_ping = false;
    plan->service_detection = false;
    plan->os_detection = false;
    plan->sudo = false;
    plan->spoof_mac_mode = CMAPER_SCAN_SPOOF_MAC_OFF;
    plan->spoof_mac_value = NULL;
    plan->traceroute = false;
    plan->udp_enrichment = false;
}

void cmaper_scan_plan_apply_profile_policy(cmaper_scan_plan_t *plan, cmaper_scan_profile_t profile) {
    if (plan == NULL) {
        return;
    }

    if (profile == CMAPER_SCAN_PROFILE_UNSET) {
        profile = CMAPER_SCAN_PROFILE_MID;
    }

    plan->profile = profile;

    switch (profile) {
    case CMAPER_SCAN_PROFILE_LOW:
        plan->timing_template = 2;
        plan->detail_workers = 8;
        plan->all_ports = false;
        plan->no_ping = false;
        plan->service_detection = false;
        plan->os_detection = false;
        plan->sudo = false;
        plan->spoof_mac_mode = CMAPER_SCAN_SPOOF_MAC_OFF;
        plan->spoof_mac_value = NULL;
        plan->traceroute = false;
        plan->udp_enrichment = false;
        return;
    case CMAPER_SCAN_PROFILE_MID:
        plan->timing_template = 3;
        plan->detail_workers = 16;
        plan->all_ports = false;
        plan->no_ping = false;
        plan->service_detection = true;
        plan->os_detection = false;
        plan->sudo = false;
        plan->spoof_mac_mode = CMAPER_SCAN_SPOOF_MAC_OFF;
        plan->spoof_mac_value = NULL;
        plan->traceroute = false;
        plan->udp_enrichment = false;
        return;
    case CMAPER_SCAN_PROFILE_HIGH:
        plan->timing_template = 4;
        plan->detail_workers = 8;
        plan->all_ports = false;
        plan->no_ping = false;
        plan->service_detection = true;
        plan->os_detection = true;
        plan->sudo = true;
        plan->spoof_mac_mode = CMAPER_SCAN_SPOOF_MAC_OFF;
        plan->spoof_mac_value = NULL;
        plan->traceroute = true;
        plan->udp_enrichment = true;
        return;
    case CMAPER_SCAN_PROFILE_UNSET:
        break;
    }
}

cmaper_err_t cmaper_scan_plan_validate(
    const cmaper_scan_plan_t *plan,
    cmaper_scan_plan_diag_t *diag
) {
    if (plan == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    cmaper_scan_plan_diag_clear(diag);

    if (plan->target == NULL || plan->target[0] == '\0') {
        cmaper_scan_plan_diag_setf(diag, "--target", "missing scan target");
        return CMAPER_ERR_CLI_USAGE;
    }

    if (plan->profile == CMAPER_SCAN_PROFILE_UNSET) {
        cmaper_scan_plan_diag_setf(diag, "--profile", "scan profile must be resolved");
        return CMAPER_ERR_CLI_USAGE;
    }

    if (plan->timing_template < 0 || plan->timing_template > 5) {
        cmaper_scan_plan_diag_setf(
            diag,
            "--timing",
            "timing template must be in range 0..5 (got: %d)",
            plan->timing_template
        );
        return CMAPER_ERR_CLI_USAGE;
    }

    if (plan->detail_workers <= 0 || plan->detail_workers > 1024) {
        cmaper_scan_plan_diag_setf(
            diag,
            "--detail-workers",
            "detail workers must be in range 1..1024 (got: %d)",
            plan->detail_workers
        );
        return CMAPER_ERR_CLI_USAGE;
    }

    if (plan->exact_ports != NULL && plan->exact_ports[0] == '\0') {
        cmaper_scan_plan_diag_setf(diag, "--ports", "exact ports cannot be empty");
        return CMAPER_ERR_CLI_USAGE;
    }

    if (plan->exact_ports != NULL && plan->all_ports) {
        cmaper_scan_plan_diag_setf(
            diag,
            "--all-ports",
            "options '--all-ports' and '--ports/--exact-ports' cannot be used together"
        );
        return CMAPER_ERR_CLI_USAGE;
    }

    if (plan->spoof_mac_mode == CMAPER_SCAN_SPOOF_MAC_CUSTOM
        && (plan->spoof_mac_value == NULL || plan->spoof_mac_value[0] == '\0')) {
        cmaper_scan_plan_diag_setf(
            diag,
            "--spoof-mac",
            "custom spoofing mode requires a non-empty value"
        );
        return CMAPER_ERR_CLI_USAGE;
    }

    return CMAPER_OK;
}

void cmaper_scan_plan_compute_capabilities(cmaper_scan_plan_t *plan) {
    bool spoofing;

    if (plan == NULL) {
        return;
    }

    spoofing = plan->spoof_mac_mode != CMAPER_SCAN_SPOOF_MAC_OFF;

    plan->capabilities.exact_ports = plan->exact_ports != NULL;
    plan->capabilities.all_ports = plan->all_ports;
    plan->capabilities.no_ping = plan->no_ping;
    plan->capabilities.service_detection = plan->service_detection;
    plan->capabilities.os_detection = plan->os_detection;
    plan->capabilities.spoof_mac = spoofing;
    plan->capabilities.traceroute = plan->traceroute;
    plan->capabilities.udp_enrichment = plan->udp_enrichment;
    plan->capabilities.privileged_required =
        plan->sudo || spoofing || plan->os_detection || plan->traceroute || plan->udp_enrichment;
}

cmaper_err_t cmaper_scan_plan_normalize(
    cmaper_scan_plan_t *plan,
    const cmaper_scan_options_t *options,
    cmaper_scan_plan_diag_t *diag
) {
    cmaper_err_t rc;

    if (plan == NULL || options == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    cmaper_scan_plan_diag_clear(diag);
    cmaper_scan_plan_init(plan);

    plan->target = options->target;
    plan->profile = options->profile;
    plan->exact_ports = options->exact_ports;

    cmaper_scan_plan_apply_defaults(plan);
    cmaper_scan_plan_apply_profile_policy(plan, plan->profile);
    cmaper_scan_plan_apply_overrides(plan, options);

    rc = cmaper_scan_plan_validate(plan, diag);
    if (rc != CMAPER_OK) {
        return rc;
    }

    cmaper_scan_plan_compute_capabilities(plan);
    return CMAPER_OK;
}

void cmaper_scan_plan_render_summary(FILE *stream, const cmaper_scan_plan_t *plan) {
    const char *target = "(none)";
    const char *ports = "default";
    const char *spoof_value = "-";

    if (stream == NULL || plan == NULL) {
        return;
    }

    if (plan->target != NULL) {
        target = plan->target;
    }

    if (plan->exact_ports != NULL) {
        ports = plan->exact_ports;
    }

    if (plan->spoof_mac_mode == CMAPER_SCAN_SPOOF_MAC_CUSTOM && plan->spoof_mac_value != NULL) {
        spoof_value = plan->spoof_mac_value;
    } else if (plan->spoof_mac_mode == CMAPER_SCAN_SPOOF_MAC_RANDOM) {
        spoof_value = "random";
    }

    fprintf(stream,
        "Normalized scan plan:\n"
        "  target: %s\n"
        "  profile: %s\n"
        "  exact-ports: %s\n"
        "  all-ports: %s\n"
        "  no-ping: %s\n"
        "  timing-template: T%d\n"
        "  detail-workers: %d\n"
        "  service-detection: %s\n"
        "  os-detection: %s\n"
        "  sudo: %s\n"
        "  spoof-mac: %s\n"
        "  spoof-mac-value: %s\n"
        "  traceroute: %s\n"
        "  udp-enrichment: %s\n"
        "Capabilities:\n"
        "  exact-ports: %s\n"
        "  all-ports: %s\n"
        "  no-ping: %s\n"
        "  service-detection: %s\n"
        "  os-detection: %s\n"
        "  spoof-mac: %s\n"
        "  traceroute: %s\n"
        "  udp-enrichment: %s\n"
        "  privileged-required: %s\n",
        target,
        cmaper_scan_profile_name(plan->profile),
        ports,
        cmaper_scan_bool_word(plan->all_ports),
        cmaper_scan_bool_word(plan->no_ping),
        plan->timing_template,
        plan->detail_workers,
        cmaper_scan_bool_word(plan->service_detection),
        cmaper_scan_bool_word(plan->os_detection),
        cmaper_scan_bool_word(plan->sudo),
        cmaper_scan_spoof_mode_name(plan->spoof_mac_mode),
        spoof_value,
        cmaper_scan_bool_word(plan->traceroute),
        cmaper_scan_bool_word(plan->udp_enrichment),
        cmaper_scan_bool_word(plan->capabilities.exact_ports),
        cmaper_scan_bool_word(plan->capabilities.all_ports),
        cmaper_scan_bool_word(plan->capabilities.no_ping),
        cmaper_scan_bool_word(plan->capabilities.service_detection),
        cmaper_scan_bool_word(plan->capabilities.os_detection),
        cmaper_scan_bool_word(plan->capabilities.spoof_mac),
        cmaper_scan_bool_word(plan->capabilities.traceroute),
        cmaper_scan_bool_word(plan->capabilities.udp_enrichment),
        cmaper_scan_bool_word(plan->capabilities.privileged_required));
}
