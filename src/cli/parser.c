#include "cmaper/cli/parser.h"

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static cmaper_log_level_t cmaper_cli_log_level_from_delta(int delta) {
    int level = (int) CMAPER_LOG_PHASE - delta;

    if (level < (int) CMAPER_LOG_PHASE) {
        return CMAPER_LOG_PHASE;
    }

    if (level > (int) CMAPER_LOG_FAIL) {
        return CMAPER_LOG_QUIET;
    }

    return (cmaper_log_level_t) level;
}

static cmaper_err_t cmaper_cli_parse_int_value(
    const char *raw_value,
    const char *option,
    int *out_value,
    cmaper_cli_diagnostic_t *diag
) {
    char *end = NULL;
    long parsed = 0;

    if (raw_value == NULL) {
        return CMAPER_OK;
    }

    errno = 0;
    parsed = strtol(raw_value, &end, 10);
    if (raw_value[0] == '\0' || end == NULL || *end != '\0' || errno == ERANGE) {
        cmaper_cli_diag_setf(
            diag,
            option,
            "invalid integer value for '%s': '%s'",
            option,
            raw_value
        );
        return CMAPER_ERR_CLI_USAGE;
    }

    if (parsed < INT_MIN || parsed > INT_MAX) {
        cmaper_cli_diag_setf(
            diag,
            option,
            "value for '%s' is out of supported range: '%s'",
            option,
            raw_value
        );
        return CMAPER_ERR_CLI_USAGE;
    }

    *out_value = (int) parsed;
    return CMAPER_OK;
}

static cmaper_err_t cmaper_cli_resolve_scan_toggle(
    bool enable_flag,
    bool disable_flag,
    const char *enable_option,
    const char *disable_option,
    cmaper_scan_toggle_t *out_toggle,
    cmaper_cli_diagnostic_t *diag
) {
    if (enable_flag && disable_flag) {
        cmaper_cli_diag_setf(
            diag,
            enable_option,
            "options '%s' and '%s' cannot be used together",
            enable_option,
            disable_option
        );
        return CMAPER_ERR_CLI_USAGE;
    }

    if (enable_flag) {
        *out_toggle = CMAPER_SCAN_TOGGLE_ENABLE;
    } else if (disable_flag) {
        *out_toggle = CMAPER_SCAN_TOGGLE_DISABLE;
    } else {
        *out_toggle = CMAPER_SCAN_TOGGLE_UNSET;
    }

    return CMAPER_OK;
}

static cmaper_err_t cmaper_cli_apply_scan_options(
    cmaper_cli_config_t *config,
    const cmaper_cli_raw_args_t *raw,
    cmaper_cli_diagnostic_t *diag
) {
    cmaper_err_t rc;

    if (raw->scan_profile != NULL) {
        config->scan.profile = cmaper_scan_profile_from_token(raw->scan_profile);
        if (config->scan.profile == CMAPER_SCAN_PROFILE_UNSET) {
            cmaper_cli_diag_setf(
                diag,
                "--profile",
                "unsupported value for '--profile': '%s' (expected: low|mid|high)",
                raw->scan_profile
            );
            return CMAPER_ERR_CLI_USAGE;
        }
    }

    config->scan.exact_ports = raw->scan_ports;

    rc = cmaper_cli_resolve_scan_toggle(
        raw->enable_no_ping,
        raw->disable_no_ping,
        "--no-ping",
        "--ping",
        &config->scan.no_ping,
        diag
    );
    if (rc != CMAPER_OK) {
        return rc;
    }

    if (raw->scan_timing != NULL) {
        rc = cmaper_cli_parse_int_value(
            raw->scan_timing,
            "--timing",
            &config->scan.timing_template,
            diag
        );
        if (rc != CMAPER_OK) {
            return rc;
        }
        config->scan.has_timing_template = true;
    }

    if (raw->scan_detail_workers != NULL) {
        rc = cmaper_cli_parse_int_value(
            raw->scan_detail_workers,
            "--detail-workers",
            &config->scan.detail_workers,
            diag
        );
        if (rc != CMAPER_OK) {
            return rc;
        }
        config->scan.has_detail_workers = true;
    }

    rc = cmaper_cli_resolve_scan_toggle(
        raw->enable_service_detection,
        raw->disable_service_detection,
        "--service-detection",
        "--no-service-detection",
        &config->scan.service_detection,
        diag
    );
    if (rc != CMAPER_OK) {
        return rc;
    }

    rc = cmaper_cli_resolve_scan_toggle(
        raw->enable_os_detection,
        raw->disable_os_detection,
        "--os-detection",
        "--no-os-detection",
        &config->scan.os_detection,
        diag
    );
    if (rc != CMAPER_OK) {
        return rc;
    }

    rc = cmaper_cli_resolve_scan_toggle(
        raw->enable_sudo,
        raw->disable_sudo,
        "--sudo",
        "--no-sudo",
        &config->scan.sudo,
        diag
    );
    if (rc != CMAPER_OK) {
        return rc;
    }

    rc = cmaper_cli_resolve_scan_toggle(
        raw->enable_traceroute,
        raw->disable_traceroute,
        "--traceroute",
        "--no-traceroute",
        &config->scan.traceroute,
        diag
    );
    if (rc != CMAPER_OK) {
        return rc;
    }

    rc = cmaper_cli_resolve_scan_toggle(
        raw->enable_udp_enrichment,
        raw->disable_udp_enrichment,
        "--udp-enrichment",
        "--no-udp-enrichment",
        &config->scan.udp_enrichment,
        diag
    );
    if (rc != CMAPER_OK) {
        return rc;
    }

    if (raw->spoof_mac != NULL && raw->disable_spoof_mac) {
        cmaper_cli_diag_set(
            diag,
            "--spoof-mac",
            "options '--spoof-mac' and '--no-spoof-mac' cannot be used together"
        );
        return CMAPER_ERR_CLI_USAGE;
    }

    if (raw->spoof_mac != NULL) {
        config->scan.spoof_mac = CMAPER_SCAN_TOGGLE_ENABLE;
        config->scan.spoof_mac_value = raw->spoof_mac;
    } else if (raw->disable_spoof_mac) {
        config->scan.spoof_mac = CMAPER_SCAN_TOGGLE_DISABLE;
    }

    return CMAPER_OK;
}

static cmaper_err_t cmaper_cli_apply_output_options(
    cmaper_cli_config_t *config,
    const cmaper_cli_raw_args_t *raw,
    cmaper_cli_diagnostic_t *diag
) {
    cmaper_output_format_t parsed_format = CMAPER_OUTPUT_FORMAT_TERMINAL;

    if (raw->format != NULL) {
        if (strcmp(raw->format, "terminal") == 0 || strcmp(raw->format, "text") == 0) {
            parsed_format = CMAPER_OUTPUT_FORMAT_TERMINAL;
        } else if (strcmp(raw->format, "markdown") == 0 || strcmp(raw->format, "md") == 0) {
            parsed_format = CMAPER_OUTPUT_FORMAT_MARKDOWN;
        } else if (strcmp(raw->format, "json") == 0) {
            parsed_format = CMAPER_OUTPUT_FORMAT_JSON;
        } else {
            cmaper_cli_diag_setf(
                diag,
                "--format",
                "unsupported value for '--format': '%s' (expected: terminal|markdown|json)",
                raw->format
            );
            return CMAPER_ERR_CLI_USAGE;
        }
    }

    if (raw->wants_color && raw->wants_no_color) {
        cmaper_cli_diag_set(diag, "--color", "options '--color' and '--no-color' cannot be used together");
        return CMAPER_ERR_CLI_USAGE;
    }

    config->output.log_level = cmaper_cli_log_level_from_delta(raw->verbosity_delta);

    if (raw->wants_no_color) {
        config->output.use_color = false;
    } else if (raw->wants_color) {
        config->output.use_color = true;
    }

    if (raw->use_json_shortcut && raw->format != NULL && parsed_format != CMAPER_OUTPUT_FORMAT_JSON) {
        cmaper_cli_diag_set(
            diag,
            "--format",
            "option '--json' conflicts with '--format' when format is not 'json'"
        );
        return CMAPER_ERR_CLI_USAGE;
    }

    if (raw->use_json_shortcut) {
        config->output.format = CMAPER_OUTPUT_FORMAT_JSON;
    } else if (raw->format != NULL) {
        config->output.format = parsed_format;
    }

    if (raw->view != NULL) {
        if (strcmp(raw->view, "compact") == 0) {
            config->output.view = CMAPER_OUTPUT_VIEW_COMPACT;
        } else if (strcmp(raw->view, "full") == 0) {
            config->output.view = CMAPER_OUTPUT_VIEW_FULL;
        } else {
            cmaper_cli_diag_setf(
                diag,
                "--view",
                "unsupported value for '--view': '%s' (expected: compact|full)",
                raw->view
            );
            return CMAPER_ERR_CLI_USAGE;
        }
    }

    if (raw->output != NULL) {
        if (strcmp(raw->output, "terminal") == 0) {
            config->output.target = CMAPER_OUTPUT_TARGET_TERMINAL;
            config->output.target_path = NULL;
        } else if (strcmp(raw->output, "clipboard") == 0) {
            config->output.target = CMAPER_OUTPUT_TARGET_CLIPBOARD;
            config->output.target_path = NULL;
        } else if (strncmp(raw->output, "file:", 5) == 0) {
            if (raw->output[5] == '\0') {
                cmaper_cli_diag_set(
                    diag,
                    "--output",
                    "output target 'file:<path>' requires a non-empty path"
                );
                return CMAPER_ERR_CLI_USAGE;
            }
            config->output.target = CMAPER_OUTPUT_TARGET_FILE;
            config->output.target_path = raw->output + 5;
        } else {
            cmaper_cli_diag_setf(
                diag,
                "--output",
                "unsupported value for '--output': '%s' (expected: terminal|clipboard|file:<path>)",
                raw->output
            );
            return CMAPER_ERR_CLI_USAGE;
        }
    }

    return CMAPER_OK;
}

static cmaper_err_t cmaper_cli_parse_limit(
    cmaper_cli_config_t *config,
    const cmaper_cli_raw_args_t *raw,
    cmaper_cli_diagnostic_t *diag
) {
    char *end = NULL;
    long parsed = 0;

    if (raw->limit == NULL) {
        return CMAPER_OK;
    }

    errno = 0;
    parsed = strtol(raw->limit, &end, 10);
    if (raw->limit[0] == '\0' || end == NULL || *end != '\0' || errno == ERANGE) {
        cmaper_cli_diag_setf(
            diag,
            "--limit",
            "invalid integer value for '--limit': '%s'",
            raw->limit
        );
        return CMAPER_ERR_CLI_USAGE;
    }

    if (parsed < INT_MIN || parsed > INT_MAX) {
        cmaper_cli_diag_setf(
            diag,
            "--limit",
            "value for '--limit' is out of supported range: '%s'",
            raw->limit
        );
        return CMAPER_ERR_CLI_USAGE;
    }

    config->history.limit = (int) parsed;
    config->history.has_limit = true;
    return CMAPER_OK;
}

static cmaper_err_t cmaper_cli_unexpected_positionals(
    const cmaper_cli_raw_args_t *raw,
    size_t consumed,
    cmaper_cli_diagnostic_t *diag
) {
    if (consumed == raw->positional_count) {
        return CMAPER_OK;
    }

    cmaper_cli_diag_setf(
        diag,
        raw->positionals[consumed],
        "unexpected positional argument '%s'",
        raw->positionals[consumed]
    );
    return CMAPER_ERR_CLI_USAGE;
}

static cmaper_err_t cmaper_cli_apply_mode_positionals(
    cmaper_cli_config_t *config,
    const cmaper_cli_raw_args_t *raw,
    cmaper_cli_diagnostic_t *diag
) {
    size_t idx = 0;

    switch (config->mode) {
    case CMAPER_CLI_MODE_SCAN:
        if (config->scan.target == NULL && idx < raw->positional_count) {
            config->scan.target = raw->positionals[idx++];
        }
        break;
    case CMAPER_CLI_MODE_SESSION:
    case CMAPER_CLI_MODE_TIMELINE:
    case CMAPER_CLI_MODE_DEVICES:
    case CMAPER_CLI_MODE_POSTURE:
    case CMAPER_CLI_MODE_DELETE_SESSION:
        if (config->history.session_id == NULL && idx < raw->positional_count) {
            config->history.session_id = raw->positionals[idx++];
        }
        break;
    case CMAPER_CLI_MODE_DEVICE:
        if (config->history.session_id == NULL && idx < raw->positional_count) {
            config->history.session_id = raw->positionals[idx++];
        }
        if (config->history.device_id == NULL && idx < raw->positional_count) {
            config->history.device_id = raw->positionals[idx++];
        }
        break;
    case CMAPER_CLI_MODE_DIFF:
    case CMAPER_CLI_MODE_DIFF_GLOBAL:
        if (config->history.from_session_id == NULL && idx < raw->positional_count) {
            config->history.from_session_id = raw->positionals[idx++];
        }
        if (config->history.to_session_id == NULL && idx < raw->positional_count) {
            config->history.to_session_id = raw->positionals[idx++];
        }
        break;
    case CMAPER_CLI_MODE_SESSIONS:
    case CMAPER_CLI_MODE_DELETE_ALL_SESSIONS:
    case CMAPER_CLI_MODE_CHECK:
    case CMAPER_CLI_MODE_NONE:
        break;
    }

    if ((config->mode == CMAPER_CLI_MODE_TIMELINE || config->mode == CMAPER_CLI_MODE_POSTURE)
        && config->history.device_id == NULL
        && idx < raw->positional_count) {
        config->history.device_id = raw->positionals[idx++];
    }

    return cmaper_cli_unexpected_positionals(raw, idx, diag);
}

static cmaper_err_t cmaper_cli_apply_intent(
    cmaper_cli_config_t *config,
    const cmaper_cli_raw_args_t *raw,
    cmaper_cli_diagnostic_t *diag
) {
    if (raw->wants_help && raw->wants_version) {
        cmaper_cli_diag_set(diag, "--help", "options '--help' and '--version' cannot be used together");
        return CMAPER_ERR_CLI_USAGE;
    }

    if (raw->wants_version) {
        if (raw->mode_token != NULL || raw->positional_count > 0) {
            cmaper_cli_diag_set(diag, "--version", "option '--version' does not accept command arguments");
            return CMAPER_ERR_CLI_USAGE;
        }
        config->intent = CMAPER_CLI_INTENT_VERSION;
        return CMAPER_OK;
    }

    if (raw->wants_help) {
        config->intent = CMAPER_CLI_INTENT_HELP;
        config->help_topic = raw->mode_token;
        if (raw->positional_count > 0) {
            cmaper_cli_diag_set(diag, raw->positionals[0], "too many arguments for help");
            return CMAPER_ERR_CLI_USAGE;
        }
        return CMAPER_OK;
    }

    if (raw->wants_check) {
        if (raw->mode_token != NULL || raw->positional_count > 0) {
            cmaper_cli_diag_set(
                diag,
                "--check",
                "option '--check' does not accept command arguments"
            );
            return CMAPER_ERR_CLI_USAGE;
        }
        config->mode = CMAPER_CLI_MODE_CHECK;
        return CMAPER_OK;
    }

    if (raw->mode_token == NULL) {
        cmaper_cli_diag_set(diag, NULL, "missing command mode");
        return CMAPER_ERR_CLI_USAGE;
    }

    if (strcmp(raw->mode_token, "help") == 0) {
        config->intent = CMAPER_CLI_INTENT_HELP;
        if (raw->positional_count > 1) {
            cmaper_cli_diag_set(diag, raw->positionals[1], "too many arguments for help");
            return CMAPER_ERR_CLI_USAGE;
        }
        config->help_topic = raw->positional_count == 1 ? raw->positionals[0] : NULL;
        return CMAPER_OK;
    }

    if (strcmp(raw->mode_token, "version") == 0) {
        config->intent = CMAPER_CLI_INTENT_VERSION;
        if (raw->positional_count > 0) {
            cmaper_cli_diag_set(diag, raw->positionals[0], "command 'version' does not accept positional arguments");
            return CMAPER_ERR_CLI_USAGE;
        }
        return CMAPER_OK;
    }

    config->mode = cmaper_cli_mode_from_token(raw->mode_token);
    if (!cmaper_cli_mode_is_defined(config->mode)) {
        cmaper_cli_diag_setf(diag, raw->mode_token, "unknown mode '%s'", raw->mode_token);
        return CMAPER_ERR_CLI_USAGE;
    }

    return CMAPER_OK;
}

cmaper_err_t cmaper_cli_normalize_config(
    cmaper_cli_config_t *config,
    const cmaper_cli_raw_args_t *raw,
    cmaper_cli_diagnostic_t *diag
) {
    cmaper_err_t rc;

    if (config == NULL || raw == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    cmaper_cli_diag_clear(diag);
    cmaper_cli_config_init(config);

    rc = cmaper_cli_apply_output_options(config, raw, diag);
    if (rc != CMAPER_OK) {
        return rc;
    }

    rc = cmaper_cli_apply_intent(config, raw, diag);
    if (rc != CMAPER_OK || config->intent != CMAPER_CLI_INTENT_EXECUTE) {
        return rc;
    }

    config->scan.target = raw->target;
    config->history.session_id = raw->session_id;
    config->history.from_session_id = raw->from_session_id;
    config->history.to_session_id = raw->to_session_id;
    config->history.device_id = raw->device_id;
    config->dev_mode = raw->wants_dev;
    config->xml_only = raw->xml_only;
    config->confirm_delete_all = raw->confirm_delete_all;

    rc = cmaper_cli_apply_scan_options(config, raw, diag);
    if (rc != CMAPER_OK) {
        return rc;
    }

    rc = cmaper_cli_parse_limit(config, raw, diag);
    if (rc != CMAPER_OK) {
        return rc;
    }

    return cmaper_cli_apply_mode_positionals(config, raw, diag);
}
