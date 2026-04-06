#include "cmaper/scan/internal/detail_internal.h"

#include <string.h>

#include "cmaper/scan/command.h"

static int cmaper_scan_detail_phase_hard_timeout_seconds(
    const cmaper_scan_plan_t *plan,
    const char *phase_label
) {
    int timeout_seconds = 0;
    cmaper_scan_profile_t profile = CMAPER_SCAN_PROFILE_MID;

    if (plan != NULL) {
        profile = plan->profile;
    }

    if (phase_label != NULL && strncmp(phase_label, "detail-probe", 12) == 0) {
        switch (profile) {
        case CMAPER_SCAN_PROFILE_LOW:
            timeout_seconds = 240;
            break;
        case CMAPER_SCAN_PROFILE_MID:
            timeout_seconds = 420;
            break;
        case CMAPER_SCAN_PROFILE_HIGH:
            timeout_seconds = 600;
            break;
        case CMAPER_SCAN_PROFILE_UNSET:
            timeout_seconds = 420;
            break;
        }
    } else {
        switch (profile) {
        case CMAPER_SCAN_PROFILE_LOW:
            timeout_seconds = 300;
            break;
        case CMAPER_SCAN_PROFILE_MID:
            timeout_seconds = 540;
            break;
        case CMAPER_SCAN_PROFILE_HIGH:
            timeout_seconds = 780;
            break;
        case CMAPER_SCAN_PROFILE_UNSET:
            timeout_seconds = 540;
            break;
        }
    }

    if (plan != NULL && plan->all_ports) {
        timeout_seconds += 480;
    }

    return timeout_seconds;
}

cmaper_err_t cmaper_scan_detail_run_command(
    const cmaper_scan_detail_request_t *request,
    const cmaper_scan_detail_command_t *command,
    const char *phase_label,
    int heartbeat_seconds,
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
    process_request.heartbeat_seconds = heartbeat_seconds;
    process_request.heartbeat_label = phase_label;
    process_request.hard_timeout_seconds = cmaper_scan_detail_phase_hard_timeout_seconds(
        request->plan,
        phase_label
    );

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
