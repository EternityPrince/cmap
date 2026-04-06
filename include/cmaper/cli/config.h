#ifndef CMAPER_CLI_CONFIG_H
#define CMAPER_CLI_CONFIG_H

#include <stdbool.h>

#include "cmaper/core/log.h"
#include "cmaper/scan/options.h"

typedef enum {
    CMAPER_CLI_INTENT_EXECUTE = 0,
    CMAPER_CLI_INTENT_HELP,
    CMAPER_CLI_INTENT_VERSION
} cmaper_cli_intent_t;

typedef enum {
    CMAPER_CLI_MODE_NONE = 0,
    CMAPER_CLI_MODE_SCAN,
    CMAPER_CLI_MODE_SESSIONS,
    CMAPER_CLI_MODE_SESSION,
    CMAPER_CLI_MODE_DIFF,
    CMAPER_CLI_MODE_DIFF_GLOBAL,
    CMAPER_CLI_MODE_TIMELINE,
    CMAPER_CLI_MODE_DEVICES,
    CMAPER_CLI_MODE_DEVICE,
    CMAPER_CLI_MODE_POSTURE,
    CMAPER_CLI_MODE_DELETE_SESSION,
    CMAPER_CLI_MODE_DELETE_ALL_SESSIONS,
    CMAPER_CLI_MODE_CHECK
} cmaper_cli_mode_t;

typedef enum {
    CMAPER_OUTPUT_FORMAT_TERMINAL = 0,
    CMAPER_OUTPUT_FORMAT_TEXT = CMAPER_OUTPUT_FORMAT_TERMINAL,
    CMAPER_OUTPUT_FORMAT_MARKDOWN,
    CMAPER_OUTPUT_FORMAT_JSON
} cmaper_output_format_t;

typedef enum {
    CMAPER_OUTPUT_VIEW_COMPACT = 0,
    CMAPER_OUTPUT_VIEW_FULL
} cmaper_output_view_t;

typedef enum {
    CMAPER_OUTPUT_TARGET_TERMINAL = 0,
    CMAPER_OUTPUT_TARGET_FILE,
    CMAPER_OUTPUT_TARGET_CLIPBOARD
} cmaper_output_target_t;

typedef struct {
    const char *session_id;
    const char *from_session_id;
    const char *to_session_id;
    const char *device_id;
    int limit;
    bool has_limit;
} cmaper_history_filters_t;

typedef struct {
    cmaper_output_format_t format;
    cmaper_output_view_t view;
    cmaper_output_target_t target;
    const char *target_path;
    cmaper_log_level_t log_level;
    bool use_color;
} cmaper_output_options_t;

typedef struct {
    cmaper_cli_intent_t intent;
    cmaper_cli_mode_t mode;
    const char *help_topic;
    cmaper_scan_options_t scan;
    cmaper_history_filters_t history;
    cmaper_output_options_t output;
    bool dev_mode;
    bool xml_only;
    bool confirm_delete_all;
} cmaper_cli_config_t;

void cmaper_cli_config_init(cmaper_cli_config_t *config);
bool cmaper_cli_mode_is_defined(cmaper_cli_mode_t mode);
cmaper_cli_mode_t cmaper_cli_mode_from_token(const char *token);
const char *cmaper_cli_mode_name(cmaper_cli_mode_t mode);

const char *cmaper_output_format_name(cmaper_output_format_t format);
const char *cmaper_output_view_name(cmaper_output_view_t view);
const char *cmaper_output_target_name(cmaper_output_target_t target);

#endif
