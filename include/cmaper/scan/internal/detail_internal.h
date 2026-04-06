#ifndef CMAPER_SCAN_INTERNAL_DETAIL_INTERNAL_H
#define CMAPER_SCAN_INTERNAL_DETAIL_INTERNAL_H

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>

#include "cmaper/scan/command.h"
#include "cmaper/scan/detail.h"

#define CMAPER_SCAN_SUDO_BIN "/usr/bin/sudo"

#define CMAPER_SCAN_DETAIL_CMD_MAX_ARGS 48
#define CMAPER_SCAN_DETAIL_CMD_ARG_CAP 512
#define CMAPER_SCAN_DETAIL_CMD_RENDER_CAP 2048
#define CMAPER_SCAN_DETAIL_PROGRESS_INTERVAL_MS 1000LL
#define CMAPER_SCAN_DETAIL_PROGRESS_SLEEP_NS 250000000L

typedef struct {
    int argc;
    char args[CMAPER_SCAN_DETAIL_CMD_MAX_ARGS][CMAPER_SCAN_DETAIL_CMD_ARG_CAP];
    const char *argv[CMAPER_SCAN_DETAIL_CMD_MAX_ARGS + 1];
    char rendered[CMAPER_SCAN_DETAIL_CMD_RENDER_CAP];
} cmaper_scan_detail_command_t;

typedef struct {
    bool enabled;
    cmaper_spoof_suppression_t suppression;
    char value[32];
} cmaper_scan_detail_spoof_policy_t;

typedef enum {
    CMAPER_SCAN_DETAIL_PROBE_TRANSPORT_DEFAULT = 0,
    CMAPER_SCAN_DETAIL_PROBE_TRANSPORT_TCP_CONNECT
} cmaper_scan_detail_probe_transport_t;

typedef enum {
    CMAPER_SCAN_DETAIL_STAGE_QUEUED = 0,
    CMAPER_SCAN_DETAIL_STAGE_DIRECT,
    CMAPER_SCAN_DETAIL_STAGE_PROBE,
    CMAPER_SCAN_DETAIL_STAGE_ENRICHMENT,
    CMAPER_SCAN_DETAIL_STAGE_DONE,
    CMAPER_SCAN_DETAIL_STAGE_DEGRADED,
    CMAPER_SCAN_DETAIL_STAGE_FAILED
} cmaper_scan_detail_stage_t;

typedef struct {
    char ip[CMAPER_SCAN_DETAIL_TARGET_IP_CAP];
    cmaper_scan_detail_stage_t stage;
    bool started;
    long long started_ms;
    bool finished;
    long long finished_ms;
    bool open_ports_known;
    size_t open_ports;
    bool scripts_known;
    size_t scripts_count;
} cmaper_scan_detail_host_progress_t;

typedef struct {
    const cmaper_scan_detail_request_t *request;
    cmaper_scan_detail_host_progress_t *hosts;
    size_t host_count;
    bool stop_requested;
    bool lock_initialized;
    bool dynamic_render;
    size_t spinner_index;
    size_t rendered_lines;
    pthread_mutex_t lock;
} cmaper_scan_detail_progress_state_t;

void cmaper_scan_detail_progress_mark_stage(
    cmaper_scan_detail_progress_state_t *state,
    size_t index,
    cmaper_scan_detail_stage_t stage
);

void cmaper_scan_detail_progress_set_open_ports(
    cmaper_scan_detail_progress_state_t *state,
    size_t index,
    size_t open_ports
);

void cmaper_scan_detail_progress_set_scripts(
    cmaper_scan_detail_progress_state_t *state,
    size_t index,
    size_t scripts_count
);

void *cmaper_scan_detail_progress_thread(void *arg);

void cmaper_scan_detail_progress_shutdown(
    cmaper_scan_detail_progress_state_t *state,
    bool *thread_started,
    pthread_t *thread,
    bool emit_final_snapshot
);

void cmaper_scan_detail_spoof_policy_resolve(
    const cmaper_scan_plan_t *plan,
    const cmaper_scan_source_identity_t *source_identity,
    cmaper_scan_detail_spoof_policy_t *policy
);

cmaper_err_t cmaper_scan_detail_build_probe_command(
    const cmaper_scan_detail_request_t *request,
    const cmaper_scan_detail_target_t *target,
    const char *xml_output_path,
    const cmaper_scan_detail_spoof_policy_t *spoof_policy,
    cmaper_scan_detail_command_t *command
);

cmaper_err_t cmaper_scan_detail_build_probe_command_with_transport(
    const cmaper_scan_detail_request_t *request,
    const cmaper_scan_detail_target_t *target,
    cmaper_scan_detail_probe_transport_t transport,
    const char *xml_output_path,
    const cmaper_scan_detail_spoof_policy_t *spoof_policy,
    cmaper_scan_detail_command_t *command
);

cmaper_err_t cmaper_scan_detail_build_enrichment_like_command(
    const cmaper_scan_detail_request_t *request,
    const char *ip,
    const int *ports,
    size_t port_count,
    const char *xml_output_path,
    const cmaper_scan_detail_spoof_policy_t *spoof_policy,
    cmaper_scan_detail_command_t *command
);

cmaper_err_t cmaper_scan_detail_run_command(
    const cmaper_scan_detail_request_t *request,
    const cmaper_scan_detail_command_t *command,
    const char *phase_label,
    int heartbeat_seconds,
    const char *xml_output_path,
    char **out_stderr_data,
    size_t *out_stderr_size
);

void cmaper_scan_detail_execute_for_target(
    const cmaper_scan_detail_request_t *request,
    const cmaper_scan_detail_target_t *target,
    size_t target_index,
    cmaper_scan_detail_host_result_t *host_result,
    cmaper_scan_detail_progress_state_t *progress_state
);

#endif
