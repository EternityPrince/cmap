#include "cmaper/history/internal/service_internal.h"

#include <limits.h>
#include <stdio.h>

static int cmaper_history_default_limit(cmaper_cli_mode_t mode) {
    switch (mode) {
    case CMAPER_CLI_MODE_SESSIONS:
        return 20;
    case CMAPER_CLI_MODE_DEVICES:
        return 50;
    case CMAPER_CLI_MODE_TIMELINE:
        return 20;
    case CMAPER_CLI_MODE_SCAN:
    case CMAPER_CLI_MODE_SESSION:
    case CMAPER_CLI_MODE_DIFF:
    case CMAPER_CLI_MODE_DIFF_GLOBAL:
    case CMAPER_CLI_MODE_DEVICE:
    case CMAPER_CLI_MODE_POSTURE:
    case CMAPER_CLI_MODE_DELETE_SESSION:
    case CMAPER_CLI_MODE_DELETE_ALL_SESSIONS:
    case CMAPER_CLI_MODE_CHECK:
    case CMAPER_CLI_MODE_NONE:
        break;
    }

    return 0;
}

static int cmaper_history_limit_for_mode(const cmaper_cli_config_t *config) {
    if (config == NULL) {
        return 0;
    }
    if (config->history.has_limit) {
        return config->history.limit;
    }
    return cmaper_history_default_limit(config->mode);
}

sqlite3_int64 cmaper_history_resolve_filter_device_id(
    sqlite3 *db,
    const char *device_token,
    bool *out_has_filter,
    bool *out_found
) {
    static const sqlite3_int64 MISSING_SENTINEL = LLONG_MAX;
    sqlite3_int64 device_id = 0;

    if (out_has_filter != NULL) {
        *out_has_filter = false;
    }
    if (out_found != NULL) {
        *out_found = false;
    }

    if (device_token == NULL || device_token[0] == '\0') {
        return 0;
    }

    if (out_has_filter != NULL) {
        *out_has_filter = true;
    }

    if (db == NULL) {
        return MISSING_SENTINEL;
    }

    if (cmaper_history_query_resolve_device(db, device_token, &device_id) != CMAPER_OK) {
        return MISSING_SENTINEL;
    }

    if (device_id > 0) {
        if (out_found != NULL) {
            *out_found = true;
        }
        return device_id;
    }

    return MISSING_SENTINEL;
}

cmaper_err_t cmaper_history_run_sessions(
    sqlite3 *db,
    bool db_available,
    const cmaper_cli_config_t *config,
    FILE *report_stream,
    const cmaper_history_render_options_t *render_options
) {
    cmaper_history_sessions_report_t report;
    cmaper_err_t rc = CMAPER_OK;

    cmaper_history_sessions_report_init(&report);
    if (db_available) {
        rc = cmaper_history_query_sessions(db, cmaper_history_limit_for_mode(config), &report);
        if (rc != CMAPER_OK) {
            cmaper_history_sessions_report_dispose(&report);
            return rc;
        }
    } else {
        report.db_available = false;
        report.limit = cmaper_history_limit_for_mode(config);
    }

    cmaper_history_render_sessions(report_stream, render_options, &report);
    cmaper_history_sessions_report_dispose(&report);
    return CMAPER_OK;
}

cmaper_err_t cmaper_history_run_session_detail(
    sqlite3 *db,
    bool db_available,
    const cmaper_cli_config_t *config,
    FILE *report_stream,
    const cmaper_history_render_options_t *render_options
) {
    cmaper_history_session_report_t report;
    cmaper_history_session_ref_t session_ref;
    cmaper_err_t rc = CMAPER_OK;

    cmaper_history_session_report_init(&report);
    cmaper_history_session_ref_init(&session_ref);

    if (db_available) {
        rc = cmaper_history_query_resolve_session(db, config->history.session_id, &session_ref);
        if (rc != CMAPER_OK) {
            cmaper_history_session_report_dispose(&report);
            return rc;
        }

        rc = cmaper_history_query_session_detail(db, &session_ref, &report);
        if (rc != CMAPER_OK) {
            cmaper_history_session_report_dispose(&report);
            return rc;
        }
    } else {
        report.db_available = false;
        cmaper_history_copy_string(
            report.summary.session_id,
            sizeof(report.summary.session_id),
            config->history.session_id
        );
    }

    cmaper_history_render_session(report_stream, render_options, &report);
    cmaper_history_session_report_dispose(&report);
    return CMAPER_OK;
}

cmaper_err_t cmaper_history_run_devices(
    sqlite3 *db,
    bool db_available,
    const cmaper_cli_config_t *config,
    FILE *report_stream,
    const cmaper_history_render_options_t *render_options
) {
    cmaper_history_devices_report_t report;
    cmaper_history_session_ref_t session_ref;
    cmaper_err_t rc = CMAPER_OK;

    cmaper_history_devices_report_init(&report);
    cmaper_history_session_ref_init(&session_ref);

    if (db_available) {
        rc = cmaper_history_query_resolve_session(db, config->history.session_id, &session_ref);
        if (rc != CMAPER_OK) {
            cmaper_history_devices_report_dispose(&report);
            return rc;
        }

        rc = cmaper_history_query_devices(
            db,
            &session_ref,
            cmaper_history_limit_for_mode(config),
            &report
        );
        if (rc != CMAPER_OK) {
            cmaper_history_devices_report_dispose(&report);
            return rc;
        }
    } else {
        report.db_available = false;
        report.limit = cmaper_history_limit_for_mode(config);
        cmaper_history_copy_string(report.session_id, sizeof(report.session_id), config->history.session_id);
    }

    cmaper_history_render_devices(report_stream, render_options, &report);
    cmaper_history_devices_report_dispose(&report);
    return CMAPER_OK;
}

cmaper_err_t cmaper_history_run_device(
    sqlite3 *db,
    bool db_available,
    const cmaper_cli_config_t *config,
    FILE *report_stream,
    const cmaper_history_render_options_t *render_options
) {
    cmaper_history_device_report_t report;
    cmaper_history_session_ref_t session_ref;
    sqlite3_int64 device_id = 0;
    cmaper_err_t rc = CMAPER_OK;

    cmaper_history_device_report_init(&report);
    cmaper_history_session_ref_init(&session_ref);

    if (db_available) {
        rc = cmaper_history_query_resolve_session(db, config->history.session_id, &session_ref);
        if (rc != CMAPER_OK) {
            cmaper_history_device_report_dispose(&report);
            return rc;
        }

        rc = cmaper_history_query_resolve_device(db, config->history.device_id, &device_id);
        if (rc != CMAPER_OK) {
            cmaper_history_device_report_dispose(&report);
            return rc;
        }

        if (device_id > 0) {
            rc = cmaper_history_query_device(db, &session_ref, device_id, &report);
            if (rc != CMAPER_OK) {
                cmaper_history_device_report_dispose(&report);
                return rc;
            }
        } else {
            report.db_available = true;
            report.session_found = session_ref.found;
            if (session_ref.found) {
                cmaper_history_copy_string(
                    report.session_id,
                    sizeof(report.session_id),
                    session_ref.session_uid
                );
            }
            cmaper_history_copy_string(
                report.device_id,
                sizeof(report.device_id),
                config->history.device_id
            );
        }
    } else {
        report.db_available = false;
        cmaper_history_copy_string(report.session_id, sizeof(report.session_id), config->history.session_id);
        cmaper_history_copy_string(report.device_id, sizeof(report.device_id), config->history.device_id);
    }

    cmaper_history_render_device(report_stream, render_options, &report);
    cmaper_history_device_report_dispose(&report);
    return CMAPER_OK;
}

cmaper_err_t cmaper_history_run_timeline(
    sqlite3 *db,
    bool db_available,
    const cmaper_cli_config_t *config,
    FILE *report_stream,
    const cmaper_history_render_options_t *render_options
) {
    cmaper_history_timeline_report_t report;
    cmaper_history_session_ref_t anchor_ref;
    sqlite3_int64 device_id = 0;
    bool has_filter = false;
    bool filter_found = false;
    cmaper_err_t rc = CMAPER_OK;

    cmaper_history_timeline_report_init(&report);
    cmaper_history_session_ref_init(&anchor_ref);

    if (db_available) {
        rc = cmaper_history_query_resolve_session(db, config->history.session_id, &anchor_ref);
        if (rc != CMAPER_OK) {
            cmaper_history_timeline_report_dispose(&report);
            return rc;
        }

        device_id = cmaper_history_resolve_filter_device_id(
            db,
            config->history.device_id,
            &has_filter,
            &filter_found
        );

        rc = cmaper_history_query_timeline(
            db,
            &anchor_ref,
            device_id,
            cmaper_history_limit_for_mode(config),
            &report
        );
        if (rc != CMAPER_OK) {
            cmaper_history_timeline_report_dispose(&report);
            return rc;
        }

        if (report.anchor_session_id[0] == '\0') {
            cmaper_history_copy_string(
                report.anchor_session_id,
                sizeof(report.anchor_session_id),
                config->history.session_id
            );
        }

        if (has_filter) {
            report.has_device_filter = true;
            if (filter_found) {
                (void) snprintf(report.device_id, sizeof(report.device_id), "%lld", (long long) device_id);
            } else {
                cmaper_history_copy_string(
                    report.device_id,
                    sizeof(report.device_id),
                    config->history.device_id
                );
            }
        }
    } else {
        report.db_available = false;
        report.limit = cmaper_history_limit_for_mode(config);
        report.has_device_filter = config->history.device_id != NULL;
        cmaper_history_copy_string(
            report.anchor_session_id,
            sizeof(report.anchor_session_id),
            config->history.session_id
        );
        if (config->history.device_id != NULL) {
            cmaper_history_copy_string(
                report.device_id,
                sizeof(report.device_id),
                config->history.device_id
            );
        }
    }

    cmaper_history_render_timeline(report_stream, render_options, &report);
    cmaper_history_timeline_report_dispose(&report);
    return CMAPER_OK;
}
