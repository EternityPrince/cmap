#include "cmaper/cli/config.h"

#include <stddef.h>
#include <string.h>

void cmaper_cli_config_init(cmaper_cli_config_t *config) {
    if (config == NULL) {
        return;
    }

    config->intent = CMAPER_CLI_INTENT_EXECUTE;
    config->mode = CMAPER_CLI_MODE_NONE;
    config->help_topic = NULL;

    cmaper_scan_options_init(&config->scan);

    config->history.session_id = NULL;
    config->history.from_session_id = NULL;
    config->history.to_session_id = NULL;
    config->history.device_id = NULL;
    config->history.limit = 0;
    config->history.has_limit = false;

    config->output.format = CMAPER_OUTPUT_FORMAT_TERMINAL;
    config->output.view = CMAPER_OUTPUT_VIEW_COMPACT;
    config->output.target = CMAPER_OUTPUT_TARGET_TERMINAL;
    config->output.target_path = NULL;
    config->output.log_level = CMAPER_LOG_WAIT;
    config->output.use_color = true;

    config->dev_mode = false;
    config->xml_only = false;
    config->confirm_delete_all = false;
}

bool cmaper_cli_mode_is_defined(cmaper_cli_mode_t mode) {
    return mode >= CMAPER_CLI_MODE_SCAN && mode <= CMAPER_CLI_MODE_CHECK;
}

cmaper_cli_mode_t cmaper_cli_mode_from_token(const char *token) {
    if (token == NULL || token[0] == '\0') {
        return CMAPER_CLI_MODE_NONE;
    }

    if (strcmp(token, "scan") == 0) {
        return CMAPER_CLI_MODE_SCAN;
    }
    if (strcmp(token, "sessions") == 0) {
        return CMAPER_CLI_MODE_SESSIONS;
    }
    if (strcmp(token, "session") == 0) {
        return CMAPER_CLI_MODE_SESSION;
    }
    if (strcmp(token, "diff") == 0) {
        return CMAPER_CLI_MODE_DIFF;
    }
    if (strcmp(token, "diff-global") == 0) {
        return CMAPER_CLI_MODE_DIFF_GLOBAL;
    }
    if (strcmp(token, "timeline") == 0) {
        return CMAPER_CLI_MODE_TIMELINE;
    }
    if (strcmp(token, "devices") == 0) {
        return CMAPER_CLI_MODE_DEVICES;
    }
    if (strcmp(token, "device") == 0) {
        return CMAPER_CLI_MODE_DEVICE;
    }
    if (strcmp(token, "posture") == 0) {
        return CMAPER_CLI_MODE_POSTURE;
    }
    if (strcmp(token, "delete-session") == 0) {
        return CMAPER_CLI_MODE_DELETE_SESSION;
    }
    if (strcmp(token, "delete-all-sessions") == 0) {
        return CMAPER_CLI_MODE_DELETE_ALL_SESSIONS;
    }
    if (strcmp(token, "check") == 0) {
        return CMAPER_CLI_MODE_CHECK;
    }

    return CMAPER_CLI_MODE_NONE;
}

const char *cmaper_cli_mode_name(cmaper_cli_mode_t mode) {
    switch (mode) {
    case CMAPER_CLI_MODE_SCAN:
        return "scan";
    case CMAPER_CLI_MODE_SESSIONS:
        return "sessions";
    case CMAPER_CLI_MODE_SESSION:
        return "session";
    case CMAPER_CLI_MODE_DIFF:
        return "diff";
    case CMAPER_CLI_MODE_DIFF_GLOBAL:
        return "diff-global";
    case CMAPER_CLI_MODE_TIMELINE:
        return "timeline";
    case CMAPER_CLI_MODE_DEVICES:
        return "devices";
    case CMAPER_CLI_MODE_DEVICE:
        return "device";
    case CMAPER_CLI_MODE_POSTURE:
        return "posture";
    case CMAPER_CLI_MODE_DELETE_SESSION:
        return "delete-session";
    case CMAPER_CLI_MODE_DELETE_ALL_SESSIONS:
        return "delete-all-sessions";
    case CMAPER_CLI_MODE_CHECK:
        return "check";
    case CMAPER_CLI_MODE_NONE:
        break;
    }

    return "(none)";
}

const char *cmaper_output_format_name(cmaper_output_format_t format) {
    switch (format) {
    case CMAPER_OUTPUT_FORMAT_TERMINAL:
        return "terminal";
    case CMAPER_OUTPUT_FORMAT_MARKDOWN:
        return "markdown";
    case CMAPER_OUTPUT_FORMAT_JSON:
        return "json";
    }

    return "terminal";
}

const char *cmaper_output_view_name(cmaper_output_view_t view) {
    switch (view) {
    case CMAPER_OUTPUT_VIEW_COMPACT:
        return "compact";
    case CMAPER_OUTPUT_VIEW_FULL:
        return "full";
    }

    return "compact";
}

const char *cmaper_output_target_name(cmaper_output_target_t target) {
    switch (target) {
    case CMAPER_OUTPUT_TARGET_TERMINAL:
        return "terminal";
    case CMAPER_OUTPUT_TARGET_FILE:
        return "file";
    case CMAPER_OUTPUT_TARGET_CLIPBOARD:
        return "clipboard";
    }

    return "terminal";
}
