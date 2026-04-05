#include "cmaper/cli/validate.h"

#include <stdbool.h>
#include <string.h>

static cmaper_err_t cmaper_cli_require_value(
    const char *value,
    const char *option_name,
    cmaper_cli_diagnostic_t *diag
) {
    if (value != NULL) {
        return CMAPER_OK;
    }

    cmaper_cli_diag_setf(diag, option_name, "missing required option '%s'", option_name);
    return CMAPER_ERR_CLI_USAGE;
}

static cmaper_err_t cmaper_cli_forbid_value(
    const char *value,
    const char *option_name,
    cmaper_cli_mode_t mode,
    cmaper_cli_diagnostic_t *diag
) {
    if (value == NULL) {
        return CMAPER_OK;
    }

    cmaper_cli_diag_setf(
        diag,
        option_name,
        "option '%s' is not valid for mode '%s'",
        option_name,
        cmaper_cli_mode_name(mode)
    );
    return CMAPER_ERR_CLI_USAGE;
}

static cmaper_err_t cmaper_cli_forbid_flag(
    bool enabled,
    const char *flag_name,
    cmaper_cli_mode_t mode,
    cmaper_cli_diagnostic_t *diag
) {
    if (!enabled) {
        return CMAPER_OK;
    }

    cmaper_cli_diag_setf(
        diag,
        flag_name,
        "flag '%s' is not valid for mode '%s'",
        flag_name,
        cmaper_cli_mode_name(mode)
    );
    return CMAPER_ERR_CLI_USAGE;
}

static cmaper_err_t cmaper_cli_validate_limit(
    const cmaper_cli_config_t *config,
    bool is_allowed,
    cmaper_cli_diagnostic_t *diag
) {
    if (!config->history.has_limit) {
        return CMAPER_OK;
    }

    if (!is_allowed) {
        cmaper_cli_diag_setf(
            diag,
            "--limit",
            "option '--limit' is not valid for mode '%s'",
            cmaper_cli_mode_name(config->mode)
        );
        return CMAPER_ERR_CLI_USAGE;
    }

    if (config->history.limit <= 0) {
        cmaper_cli_diag_set(diag, "--limit", "option '--limit' must be greater than 0");
        return CMAPER_ERR_CLI_USAGE;
    }

    return CMAPER_OK;
}

static const char *cmaper_cli_option_for_toggle(
    cmaper_scan_toggle_t toggle,
    const char *enable_option,
    const char *disable_option
) {
    if (toggle == CMAPER_SCAN_TOGGLE_ENABLE) {
        return enable_option;
    }

    if (toggle == CMAPER_SCAN_TOGGLE_DISABLE) {
        return disable_option;
    }

    return NULL;
}

static cmaper_err_t cmaper_cli_forbid_scan_options(
    const cmaper_scan_options_t *scan,
    cmaper_cli_mode_t mode,
    cmaper_cli_diagnostic_t *diag
) {
    const char *toggle_option = NULL;

    if (scan == NULL) {
        return CMAPER_OK;
    }

    if (scan->target != NULL) {
        return cmaper_cli_forbid_value(scan->target, "--target", mode, diag);
    }

    if (scan->profile != CMAPER_SCAN_PROFILE_UNSET) {
        cmaper_cli_diag_setf(
            diag,
            "--profile",
            "option '--profile' is not valid for mode '%s'",
            cmaper_cli_mode_name(mode)
        );
        return CMAPER_ERR_CLI_USAGE;
    }

    if (scan->exact_ports != NULL) {
        cmaper_cli_diag_setf(
            diag,
            "--ports",
            "option '--ports' is not valid for mode '%s'",
            cmaper_cli_mode_name(mode)
        );
        return CMAPER_ERR_CLI_USAGE;
    }

    toggle_option = cmaper_cli_option_for_toggle(
        scan->no_ping,
        "--no-ping",
        "--ping"
    );
    if (toggle_option != NULL) {
        cmaper_cli_diag_setf(
            diag,
            toggle_option,
            "option '%s' is not valid for mode '%s'",
            toggle_option,
            cmaper_cli_mode_name(mode)
        );
        return CMAPER_ERR_CLI_USAGE;
    }

    if (scan->has_timing_template) {
        cmaper_cli_diag_setf(
            diag,
            "--timing",
            "option '--timing' is not valid for mode '%s'",
            cmaper_cli_mode_name(mode)
        );
        return CMAPER_ERR_CLI_USAGE;
    }

    if (scan->has_detail_workers) {
        cmaper_cli_diag_setf(
            diag,
            "--detail-workers",
            "option '--detail-workers' is not valid for mode '%s'",
            cmaper_cli_mode_name(mode)
        );
        return CMAPER_ERR_CLI_USAGE;
    }

    toggle_option = cmaper_cli_option_for_toggle(
        scan->service_detection,
        "--service-detection",
        "--no-service-detection"
    );
    if (toggle_option != NULL) {
        cmaper_cli_diag_setf(
            diag,
            toggle_option,
            "option '%s' is not valid for mode '%s'",
            toggle_option,
            cmaper_cli_mode_name(mode)
        );
        return CMAPER_ERR_CLI_USAGE;
    }

    toggle_option = cmaper_cli_option_for_toggle(
        scan->os_detection,
        "--os-detection",
        "--no-os-detection"
    );
    if (toggle_option != NULL) {
        cmaper_cli_diag_setf(
            diag,
            toggle_option,
            "option '%s' is not valid for mode '%s'",
            toggle_option,
            cmaper_cli_mode_name(mode)
        );
        return CMAPER_ERR_CLI_USAGE;
    }

    toggle_option = cmaper_cli_option_for_toggle(
        scan->sudo,
        "--sudo",
        "--no-sudo"
    );
    if (toggle_option != NULL) {
        cmaper_cli_diag_setf(
            diag,
            toggle_option,
            "option '%s' is not valid for mode '%s'",
            toggle_option,
            cmaper_cli_mode_name(mode)
        );
        return CMAPER_ERR_CLI_USAGE;
    }

    toggle_option = cmaper_cli_option_for_toggle(
        scan->spoof_mac,
        "--spoof-mac",
        "--no-spoof-mac"
    );
    if (toggle_option != NULL || scan->spoof_mac_value != NULL) {
        const char *name = toggle_option != NULL ? toggle_option : "--spoof-mac";
        cmaper_cli_diag_setf(
            diag,
            name,
            "option '%s' is not valid for mode '%s'",
            name,
            cmaper_cli_mode_name(mode)
        );
        return CMAPER_ERR_CLI_USAGE;
    }

    toggle_option = cmaper_cli_option_for_toggle(
        scan->traceroute,
        "--traceroute",
        "--no-traceroute"
    );
    if (toggle_option != NULL) {
        cmaper_cli_diag_setf(
            diag,
            toggle_option,
            "option '%s' is not valid for mode '%s'",
            toggle_option,
            cmaper_cli_mode_name(mode)
        );
        return CMAPER_ERR_CLI_USAGE;
    }

    toggle_option = cmaper_cli_option_for_toggle(
        scan->udp_enrichment,
        "--udp-enrichment",
        "--no-udp-enrichment"
    );
    if (toggle_option != NULL) {
        cmaper_cli_diag_setf(
            diag,
            toggle_option,
            "option '%s' is not valid for mode '%s'",
            toggle_option,
            cmaper_cli_mode_name(mode)
        );
        return CMAPER_ERR_CLI_USAGE;
    }

    return CMAPER_OK;
}

cmaper_err_t cmaper_cli_validate_config(
    const cmaper_cli_config_t *config,
    cmaper_cli_diagnostic_t *diag
) {
    cmaper_err_t rc;

    if (config == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    cmaper_cli_diag_clear(diag);

    if (config->intent != CMAPER_CLI_INTENT_EXECUTE) {
        return CMAPER_OK;
    }

    if (!cmaper_cli_mode_is_defined(config->mode)) {
        cmaper_cli_diag_set(diag, NULL, "mode must be specified");
        return CMAPER_ERR_CLI_USAGE;
    }

    if (config->mode != CMAPER_CLI_MODE_SCAN) {
        rc = cmaper_cli_forbid_scan_options(&config->scan, config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    if (config->xml_only && config->mode != CMAPER_CLI_MODE_SCAN) {
        cmaper_cli_diag_setf(
            diag,
            "--xml-only",
            "flag '--xml-only' is not valid for mode '%s'",
            cmaper_cli_mode_name(config->mode)
        );
        return CMAPER_ERR_CLI_USAGE;
    }

    switch (config->mode) {
    case CMAPER_CLI_MODE_SCAN:
        rc = cmaper_cli_require_value(config->scan.target, "--target", diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.session_id, "--session", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.from_session_id, "--from", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.to_session_id, "--to", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.device_id, "--device", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_flag(config->confirm_delete_all, "--yes", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        return cmaper_cli_validate_limit(config, false, diag);

    case CMAPER_CLI_MODE_SESSIONS:
        rc = cmaper_cli_forbid_value(config->scan.target, "--target", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.session_id, "--session", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.from_session_id, "--from", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.to_session_id, "--to", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.device_id, "--device", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_flag(config->confirm_delete_all, "--yes", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        return cmaper_cli_validate_limit(config, true, diag);

    case CMAPER_CLI_MODE_SESSION:
        rc = cmaper_cli_require_value(config->history.session_id, "--session", diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->scan.target, "--target", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.from_session_id, "--from", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.to_session_id, "--to", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.device_id, "--device", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_flag(config->confirm_delete_all, "--yes", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        return cmaper_cli_validate_limit(config, false, diag);

    case CMAPER_CLI_MODE_DIFF:
    case CMAPER_CLI_MODE_DIFF_GLOBAL:
        rc = cmaper_cli_require_value(config->history.from_session_id, "--from", diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_require_value(config->history.to_session_id, "--to", diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        if (strcmp(config->history.from_session_id, config->history.to_session_id) == 0) {
            cmaper_cli_diag_set(diag, "--from", "'--from' and '--to' must reference different sessions");
            return CMAPER_ERR_CLI_USAGE;
        }
        rc = cmaper_cli_forbid_value(config->scan.target, "--target", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.session_id, "--session", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.device_id, "--device", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_flag(config->confirm_delete_all, "--yes", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        return cmaper_cli_validate_limit(config, false, diag);

    case CMAPER_CLI_MODE_TIMELINE:
        rc = cmaper_cli_require_value(config->history.session_id, "--session", diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->scan.target, "--target", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.from_session_id, "--from", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.to_session_id, "--to", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_flag(config->confirm_delete_all, "--yes", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        return cmaper_cli_validate_limit(config, true, diag);

    case CMAPER_CLI_MODE_DEVICES:
        rc = cmaper_cli_require_value(config->history.session_id, "--session", diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->scan.target, "--target", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.from_session_id, "--from", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.to_session_id, "--to", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.device_id, "--device", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_flag(config->confirm_delete_all, "--yes", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        return cmaper_cli_validate_limit(config, true, diag);

    case CMAPER_CLI_MODE_DEVICE:
        rc = cmaper_cli_require_value(config->history.session_id, "--session", diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_require_value(config->history.device_id, "--device", diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->scan.target, "--target", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.from_session_id, "--from", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.to_session_id, "--to", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_flag(config->confirm_delete_all, "--yes", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        return cmaper_cli_validate_limit(config, false, diag);

    case CMAPER_CLI_MODE_POSTURE:
        rc = cmaper_cli_require_value(config->history.session_id, "--session", diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->scan.target, "--target", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.from_session_id, "--from", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.to_session_id, "--to", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_flag(config->confirm_delete_all, "--yes", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        return cmaper_cli_validate_limit(config, false, diag);

    case CMAPER_CLI_MODE_DELETE_SESSION:
        rc = cmaper_cli_require_value(config->history.session_id, "--session", diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->scan.target, "--target", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.from_session_id, "--from", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.to_session_id, "--to", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.device_id, "--device", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_flag(config->confirm_delete_all, "--yes", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        return cmaper_cli_validate_limit(config, false, diag);

    case CMAPER_CLI_MODE_DELETE_ALL_SESSIONS:
        rc = cmaper_cli_forbid_value(config->scan.target, "--target", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.session_id, "--session", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.from_session_id, "--from", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.to_session_id, "--to", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.device_id, "--device", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_validate_limit(config, false, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        return CMAPER_OK;

    case CMAPER_CLI_MODE_CHECK:
        rc = cmaper_cli_forbid_value(config->scan.target, "--target", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.session_id, "--session", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.from_session_id, "--from", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.to_session_id, "--to", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_value(config->history.device_id, "--device", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        rc = cmaper_cli_forbid_flag(config->confirm_delete_all, "--yes", config->mode, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        return cmaper_cli_validate_limit(config, false, diag);

    case CMAPER_CLI_MODE_NONE:
        break;
    }

    cmaper_cli_diag_set(diag, NULL, "mode must be specified");
    return CMAPER_ERR_CLI_USAGE;
}
