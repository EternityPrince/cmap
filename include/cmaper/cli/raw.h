#ifndef CMAPER_CLI_RAW_H
#define CMAPER_CLI_RAW_H

#include <stdbool.h>
#include <stddef.h>

#include "cmaper/cli/diagnostic.h"
#include "cmaper/core/error.h"

#define CMAPER_CLI_MAX_POSITIONALS 8

typedef struct {
    const char *program_name;
    bool wants_help;
    bool wants_version;
    bool wants_check;
    bool wants_dev;
    bool xml_only;
    int verbosity_delta;
    bool use_json_shortcut;
    bool wants_color;
    bool wants_no_color;
    bool confirm_delete_all;
    const char *mode_token;

    const char *scan_profile;
    const char *target;
    const char *scan_ports;
    bool enable_all_ports;
    bool disable_all_ports;
    bool enable_no_ping;
    bool disable_no_ping;
    const char *scan_timing;
    const char *scan_detail_workers;
    bool enable_service_detection;
    bool disable_service_detection;
    bool enable_os_detection;
    bool disable_os_detection;
    bool enable_sudo;
    bool disable_sudo;
    const char *spoof_mac;
    bool disable_spoof_mac;
    bool enable_traceroute;
    bool disable_traceroute;
    bool enable_udp_enrichment;
    bool disable_udp_enrichment;

    const char *session_id;
    const char *from_session_id;
    const char *to_session_id;
    const char *device_id;
    const char *format;
    const char *output;
    const char *view;
    const char *limit;
    size_t positional_count;
    const char *positionals[CMAPER_CLI_MAX_POSITIONALS];
} cmaper_cli_raw_args_t;

void cmaper_cli_raw_args_init(cmaper_cli_raw_args_t *raw);

cmaper_err_t cmaper_cli_parse_raw_argv(
    cmaper_cli_raw_args_t *raw,
    int argc,
    char **argv,
    cmaper_cli_diagnostic_t *diag
);

#endif
