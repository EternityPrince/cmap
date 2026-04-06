#include "cmaper/history/internal/service_internal.h"

#include <stdio.h>

#include "cmaper/output/sink.h"

static bool cmaper_history_mode_is_delete(cmaper_cli_mode_t mode) {
    return mode == CMAPER_CLI_MODE_DELETE_SESSION || mode == CMAPER_CLI_MODE_DELETE_ALL_SESSIONS;
}

cmaper_err_t cmaper_history_service_run(const cmaper_history_service_request_t *request) {
    sqlite3 *db = NULL;
    bool db_available = false;
    FILE *report_stream;
    cmaper_output_sink_t sink;
    cmaper_history_render_options_t render_options;
    cmaper_err_t rc;
    cmaper_err_t sink_rc;

    if (request == NULL || request->config == NULL || request->paths == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    report_stream = request->report_stream != NULL ? request->report_stream : stdout;
    cmaper_output_sink_init(&sink);
    render_options.format = request->config->output.format;
    render_options.view = request->config->output.view;
    render_options.use_ansi = false;

    rc = cmaper_output_sink_open(&sink, &request->config->output, report_stream, request->logger);
    if (rc != CMAPER_OK) {
        return rc;
    }
    render_options.use_ansi =
        cmaper_output_sink_should_use_ansi(&request->config->output, sink.stream);

    if (cmaper_history_mode_is_delete(request->config->mode)) {
        switch (request->config->mode) {
        case CMAPER_CLI_MODE_DELETE_SESSION:
            rc = cmaper_history_run_delete_session(request->config, request->paths, sink.stream);
            break;
        case CMAPER_CLI_MODE_DELETE_ALL_SESSIONS:
            rc = cmaper_history_run_delete_all(request->config, request->paths, sink.stream);
            break;
        case CMAPER_CLI_MODE_SCAN:
        case CMAPER_CLI_MODE_SESSIONS:
        case CMAPER_CLI_MODE_SESSION:
        case CMAPER_CLI_MODE_DIFF:
        case CMAPER_CLI_MODE_DIFF_GLOBAL:
        case CMAPER_CLI_MODE_TIMELINE:
        case CMAPER_CLI_MODE_DEVICES:
        case CMAPER_CLI_MODE_DEVICE:
        case CMAPER_CLI_MODE_POSTURE:
        case CMAPER_CLI_MODE_CHECK:
        case CMAPER_CLI_MODE_NONE:
            rc = CMAPER_ERR_INVALID_ARGUMENT;
            break;
        }

        sink_rc = cmaper_output_sink_finalize(
            &sink,
            &request->config->output,
            report_stream,
            request->logger
        );
        if (rc == CMAPER_OK && sink_rc != CMAPER_OK) {
            rc = sink_rc;
        }

        if (rc == CMAPER_OK) {
            cmaper_log(
                request->logger,
                CMAPER_LOG_OK,
                "history/service: mode '%s' completed",
                cmaper_cli_mode_name(request->config->mode)
            );
        } else {
            cmaper_log(
                request->logger,
                CMAPER_LOG_FAIL,
                "history/service: mode '%s' failed (%s)",
                cmaper_cli_mode_name(request->config->mode),
                cmaper_err_str(rc)
            );
        }
        return rc;
    }

    rc = cmaper_history_query_open_db(request->paths->db_path, &db, &db_available);
    if (rc != CMAPER_OK) {
        (void) cmaper_output_sink_finalize(
            &sink,
            &request->config->output,
            report_stream,
            request->logger
        );
        return rc;
    }

    cmaper_log(
        request->logger,
        CMAPER_LOG_PHASE,
        "history/service: mode=%s db=%s format=%s view=%s target=%s",
        cmaper_cli_mode_name(request->config->mode),
        db_available ? "available" : "missing",
        cmaper_output_format_name(render_options.format),
        cmaper_output_view_name(render_options.view),
        cmaper_output_target_name(request->config->output.target)
    );

    switch (request->config->mode) {
    case CMAPER_CLI_MODE_SESSIONS:
        rc = cmaper_history_run_sessions(
            db,
            db_available,
            request->config,
            sink.stream,
            &render_options
        );
        break;
    case CMAPER_CLI_MODE_SESSION:
        rc = cmaper_history_run_session_detail(
            db,
            db_available,
            request->config,
            sink.stream,
            &render_options
        );
        break;
    case CMAPER_CLI_MODE_DIFF:
        rc = cmaper_history_run_diff(
            db,
            db_available,
            request->config,
            sink.stream,
            &render_options,
            false
        );
        break;
    case CMAPER_CLI_MODE_DIFF_GLOBAL:
        rc = cmaper_history_run_diff(
            db,
            db_available,
            request->config,
            sink.stream,
            &render_options,
            true
        );
        break;
    case CMAPER_CLI_MODE_TIMELINE:
        rc = cmaper_history_run_timeline(
            db,
            db_available,
            request->config,
            sink.stream,
            &render_options
        );
        break;
    case CMAPER_CLI_MODE_DEVICES:
        rc = cmaper_history_run_devices(
            db,
            db_available,
            request->config,
            sink.stream,
            &render_options
        );
        break;
    case CMAPER_CLI_MODE_DEVICE:
        rc = cmaper_history_run_device(
            db,
            db_available,
            request->config,
            sink.stream,
            &render_options
        );
        break;
    case CMAPER_CLI_MODE_POSTURE:
        rc = cmaper_history_run_posture(
            db,
            db_available,
            request->config,
            sink.stream,
            &render_options
        );
        break;
    case CMAPER_CLI_MODE_SCAN:
    case CMAPER_CLI_MODE_DELETE_SESSION:
    case CMAPER_CLI_MODE_DELETE_ALL_SESSIONS:
    case CMAPER_CLI_MODE_CHECK:
    case CMAPER_CLI_MODE_NONE:
        rc = CMAPER_ERR_INVALID_ARGUMENT;
        break;
    }

    sink_rc = cmaper_output_sink_finalize(
        &sink,
        &request->config->output,
        report_stream,
        request->logger
    );
    cmaper_history_query_close_db(&db);
    if (rc == CMAPER_OK && sink_rc != CMAPER_OK) {
        rc = sink_rc;
    }

    if (rc == CMAPER_OK) {
        cmaper_log(
            request->logger,
            CMAPER_LOG_OK,
            "history/service: mode '%s' completed",
            cmaper_cli_mode_name(request->config->mode)
        );
    } else {
        cmaper_log(
            request->logger,
            CMAPER_LOG_FAIL,
            "history/service: mode '%s' failed (%s)",
            cmaper_cli_mode_name(request->config->mode),
            cmaper_err_str(rc)
        );
    }

    return rc;
}
