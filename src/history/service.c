#include "cmaper/history/service.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <sqlite3.h>

#include "cmaper/history/alerts.h"
#include "cmaper/history/delete.h"
#include "cmaper/history/diff.h"
#include "cmaper/history/domain.h"
#include "cmaper/history/query.h"
#include "cmaper/history/render.h"
#include "cmaper/output/sink.h"
#include "cmaper/platform/terminal.h"

static void cmaper_history_copy_string(char *out, size_t out_cap, const char *value) {
    if (out == NULL || out_cap == 0) {
        return;
    }

    out[0] = '\0';
    if (value == NULL) {
        return;
    }

    (void) snprintf(out, out_cap, "%s", value);
}

static bool cmaper_history_mode_is_delete(cmaper_cli_mode_t mode) {
    return mode == CMAPER_CLI_MODE_DELETE_SESSION || mode == CMAPER_CLI_MODE_DELETE_ALL_SESSIONS;
}

static bool cmaper_history_is_confirmed_yes(const char *line) {
    size_t i = 0;

    if (line == NULL) {
        return false;
    }

    while (line[i] == ' ' || line[i] == '\t' || line[i] == '\r' || line[i] == '\n') {
        i += 1U;
    }

    if (line[i] != 'y') {
        return false;
    }
    i += 1U;

    while (line[i] == ' ' || line[i] == '\t' || line[i] == '\r' || line[i] == '\n') {
        i += 1U;
    }

    return line[i] == '\0';
}

static cmaper_err_t cmaper_history_prompt_delete(
    const char *prompt_label,
    bool *out_confirmed
) {
    char answer[32];

    if (out_confirmed == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    *out_confirmed = false;

    if (!cmaper_terminal_is_tty(stdin) || !cmaper_terminal_is_tty(stderr)) {
        return CMAPER_ERR_CLI_USAGE;
    }

    fprintf(stderr, "%s Type 'y' to confirm: ", prompt_label);
    fflush(stderr);

    if (fgets(answer, sizeof(answer), stdin) == NULL) {
        return CMAPER_OK;
    }

    *out_confirmed = cmaper_history_is_confirmed_yes(answer);
    return CMAPER_OK;
}

static void cmaper_history_json_escape(FILE *stream, const char *value) {
    size_t i;

    if (stream == NULL || value == NULL) {
        return;
    }

    for (i = 0; value[i] != '\0'; ++i) {
        unsigned char ch = (unsigned char) value[i];
        switch (ch) {
        case '"':
            fputs("\\\"", stream);
            break;
        case '\\':
            fputs("\\\\", stream);
            break;
        case '\n':
            fputs("\\n", stream);
            break;
        case '\r':
            fputs("\\r", stream);
            break;
        case '\t':
            fputs("\\t", stream);
            break;
        default:
            if (ch < 32U) {
                fprintf(stream, "\\u%04x", (unsigned int) ch);
            } else {
                fputc((int) ch, stream);
            }
            break;
        }
    }
}

static void cmaper_history_json_string(FILE *stream, const char *value) {
    if (stream == NULL) {
        return;
    }

    fputc('"', stream);
    if (value != NULL) {
        cmaper_history_json_escape(stream, value);
    }
    fputc('"', stream);
}

static void cmaper_history_render_delete_report(
    FILE *stream,
    const cmaper_output_options_t *output,
    const cmaper_history_delete_report_t *report,
    bool confirmed,
    bool delete_all
) {
    cmaper_output_format_t format;

    if (stream == NULL || output == NULL || report == NULL) {
        return;
    }

    format = output->format;

    if (format == CMAPER_OUTPUT_FORMAT_JSON) {
        fputs("{\"report\":", stream);
        if (delete_all) {
            fputs("\"delete-all-sessions\",", stream);
        } else {
            fputs("\"delete-session\",", stream);
        }
        fprintf(
            stream,
            "\"confirmed\":%s,\"db_available\":%s,\"performed\":%s,",
            confirmed ? "true" : "false",
            report->db_available ? "true" : "false",
            report->performed ? "true" : "false"
        );
        if (!delete_all) {
            fputs("\"session_id\":", stream);
            cmaper_history_json_string(stream, report->session_id);
            fprintf(
                stream,
                ",\"session_found\":%s,",
                report->session_found ? "true" : "false"
            );
        }
        fprintf(
            stream,
            "\"sessions_before\":%zu,\"sessions_deleted\":%zu,\"orphan_devices_deleted\":%zu,\"orphan_networks_deleted\":%zu}\n",
            report->sessions_before,
            report->sessions_deleted,
            report->orphan_devices_deleted,
            report->orphan_networks_deleted
        );
        return;
    }

    if (format == CMAPER_OUTPUT_FORMAT_MARKDOWN) {
        fprintf(
            stream,
            "# %s\n\n- Confirmed: **%s**\n- Database available: **%s**\n- Performed: **%s**\n- Sessions before: **%zu**\n- Sessions deleted: **%zu**\n- Orphan devices deleted: **%zu**\n- Orphan networks deleted: **%zu**\n",
            delete_all ? "Delete all sessions" : "Delete session",
            confirmed ? "yes" : "no",
            report->db_available ? "yes" : "no",
            report->performed ? "yes" : "no",
            report->sessions_before,
            report->sessions_deleted,
            report->orphan_devices_deleted,
            report->orphan_networks_deleted
        );
        if (!delete_all) {
            fprintf(
                stream,
                "- Session id: `%s`\n- Session found: **%s**\n",
                report->session_id[0] != '\0' ? report->session_id : "(unknown)",
                report->session_found ? "yes" : "no"
            );
        }
        return;
    }

    fprintf(
        stream,
        "%s\n  confirmed=%s db=%s performed=%s sessions-before=%zu deleted=%zu orphan-devices=%zu orphan-networks=%zu\n",
        delete_all ? "Delete-all sessions" : "Delete session",
        confirmed ? "yes" : "no",
        report->db_available ? "ready" : "missing",
        report->performed ? "yes" : "no",
        report->sessions_before,
        report->sessions_deleted,
        report->orphan_devices_deleted,
        report->orphan_networks_deleted
    );
    if (!delete_all) {
        fprintf(
            stream,
            "  session=%s found=%s\n",
            report->session_id[0] != '\0' ? report->session_id : "(unknown)",
            report->session_found ? "yes" : "no"
        );
    }
}

static cmaper_err_t cmaper_history_run_delete_session(
    const cmaper_cli_config_t *config,
    const cmaper_runtime_paths_t *paths,
    FILE *report_stream
) {
    cmaper_history_delete_report_t report;
    bool confirmed = false;
    cmaper_err_t rc;

    if (config == NULL || paths == NULL || report_stream == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    cmaper_history_delete_report_init(&report);
    if (config->history.session_id != NULL) {
        cmaper_history_copy_string(report.session_id, sizeof(report.session_id), config->history.session_id);
    }

    rc = cmaper_history_prompt_delete("Delete session is destructive.", &confirmed);
    if (rc != CMAPER_OK) {
        if (rc == CMAPER_ERR_CLI_USAGE) {
            fprintf(stderr, "delete-session requires an interactive TTY for confirmation\n");
        }
        return rc;
    }

    if (confirmed) {
        rc = cmaper_history_delete_session(paths->db_path, config->history.session_id, &report);
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    cmaper_history_render_delete_report(report_stream, &config->output, &report, confirmed, false);
    return CMAPER_OK;
}

static cmaper_err_t cmaper_history_run_delete_all(
    const cmaper_cli_config_t *config,
    const cmaper_runtime_paths_t *paths,
    FILE *report_stream
) {
    cmaper_history_delete_report_t report;
    bool confirmed = false;
    cmaper_err_t rc;

    if (config == NULL || paths == NULL || report_stream == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    cmaper_history_delete_report_init(&report);

    rc = cmaper_history_prompt_delete("Delete all sessions is destructive.", &confirmed);
    if (rc != CMAPER_OK) {
        if (rc == CMAPER_ERR_CLI_USAGE) {
            fprintf(stderr, "delete-all-sessions requires an interactive TTY for confirmation\n");
        }
        return rc;
    }

    if (confirmed) {
        rc = cmaper_history_delete_all_sessions(paths->db_path, &report);
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    cmaper_history_render_delete_report(report_stream, &config->output, &report, confirmed, true);
    return CMAPER_OK;
}

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

static long cmaper_history_delta_size(size_t current_value, size_t previous_value) {
    if (current_value >= previous_value) {
        return (long) (current_value - previous_value);
    }
    return -((long) (previous_value - current_value));
}

static sqlite3_int64 cmaper_history_resolve_filter_device_id(
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

static cmaper_err_t cmaper_history_run_sessions(
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

static cmaper_err_t cmaper_history_run_session_detail(
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

static cmaper_err_t cmaper_history_run_devices(
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

static cmaper_err_t cmaper_history_run_device(
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

static cmaper_err_t cmaper_history_run_timeline(
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

static cmaper_err_t cmaper_history_run_diff(
    sqlite3 *db,
    bool db_available,
    const cmaper_cli_config_t *config,
    FILE *report_stream,
    const cmaper_history_render_options_t *render_options,
    bool summary_only
) {
    cmaper_history_diff_report_t report;
    cmaper_history_session_ref_t from_ref;
    cmaper_history_session_ref_t to_ref;
    cmaper_history_host_snapshot_t *from_hosts = NULL;
    cmaper_history_host_snapshot_t *to_hosts = NULL;
    size_t from_count = 0;
    size_t to_count = 0;
    cmaper_err_t rc = CMAPER_OK;

    cmaper_history_diff_report_init(&report);
    cmaper_history_session_ref_init(&from_ref);
    cmaper_history_session_ref_init(&to_ref);

    if (db_available) {
        report.db_available = true;
        rc = cmaper_history_query_resolve_session(db, config->history.from_session_id, &from_ref);
        if (rc != CMAPER_OK) {
            goto cleanup;
        }
        rc = cmaper_history_query_resolve_session(db, config->history.to_session_id, &to_ref);
        if (rc != CMAPER_OK) {
            goto cleanup;
        }

        report.from_found = from_ref.found;
        report.to_found = to_ref.found;
        if (from_ref.found) {
            cmaper_history_copy_string(
                report.from_session_id,
                sizeof(report.from_session_id),
                from_ref.session_uid
            );
        } else {
            cmaper_history_copy_string(
                report.from_session_id,
                sizeof(report.from_session_id),
                config->history.from_session_id
            );
        }
        if (to_ref.found) {
            cmaper_history_copy_string(
                report.to_session_id,
                sizeof(report.to_session_id),
                to_ref.session_uid
            );
        } else {
            cmaper_history_copy_string(
                report.to_session_id,
                sizeof(report.to_session_id),
                config->history.to_session_id
            );
        }

        if (from_ref.found && to_ref.found) {
            rc = cmaper_history_query_host_snapshots(db, from_ref.id, &from_hosts, &from_count);
            if (rc != CMAPER_OK) {
                goto cleanup;
            }
            rc = cmaper_history_query_host_snapshots(db, to_ref.id, &to_hosts, &to_count);
            if (rc != CMAPER_OK) {
                goto cleanup;
            }

            rc = cmaper_history_diff_build(from_hosts, from_count, to_hosts, to_count, &report);
            if (rc != CMAPER_OK) {
                goto cleanup;
            }
            rc = cmaper_history_alerts_build_for_diff(&report);
            if (rc != CMAPER_OK) {
                goto cleanup;
            }
        }
    } else {
        report.db_available = false;
        cmaper_history_copy_string(
            report.from_session_id,
            sizeof(report.from_session_id),
            config->history.from_session_id
        );
        cmaper_history_copy_string(
            report.to_session_id,
            sizeof(report.to_session_id),
            config->history.to_session_id
        );
    }

    cmaper_history_render_diff(report_stream, render_options, &report, summary_only);
    rc = CMAPER_OK;

cleanup:
    if (from_hosts != NULL) {
        cmaper_history_host_snapshots_dispose(from_hosts, from_count);
    }
    if (to_hosts != NULL) {
        cmaper_history_host_snapshots_dispose(to_hosts, to_count);
    }
    cmaper_history_diff_report_dispose(&report);
    return rc;
}

static cmaper_err_t cmaper_history_run_posture(
    sqlite3 *db,
    bool db_available,
    const cmaper_cli_config_t *config,
    FILE *report_stream,
    const cmaper_history_render_options_t *render_options
) {
    cmaper_history_posture_report_t report;
    cmaper_history_session_ref_t session_ref;
    cmaper_history_session_ref_t previous_ref;
    cmaper_history_posture_counters_t previous_counters;
    sqlite3_int64 device_id = 0;
    bool has_filter = false;
    bool filter_found = false;
    cmaper_err_t rc = CMAPER_OK;

    cmaper_history_posture_report_init(&report);
    cmaper_history_session_ref_init(&session_ref);
    cmaper_history_session_ref_init(&previous_ref);
    cmaper_history_posture_counters_init(&previous_counters);

    if (db_available) {
        report.db_available = true;

        rc = cmaper_history_query_resolve_session(db, config->history.session_id, &session_ref);
        if (rc != CMAPER_OK) {
            cmaper_history_posture_report_dispose(&report);
            return rc;
        }

        report.session_found = session_ref.found;
        if (session_ref.found) {
            cmaper_history_copy_string(report.session_id, sizeof(report.session_id), session_ref.session_uid);
            cmaper_history_copy_string(report.session_status, sizeof(report.session_status), session_ref.status);
            cmaper_history_copy_string(report.started_at, sizeof(report.started_at), session_ref.started_at);
            cmaper_history_copy_string(report.completed_at, sizeof(report.completed_at), session_ref.completed_at);
        } else {
            cmaper_history_copy_string(report.session_id, sizeof(report.session_id), config->history.session_id);
        }

        device_id = cmaper_history_resolve_filter_device_id(
            db,
            config->history.device_id,
            &has_filter,
            &filter_found
        );
        report.has_device_filter = has_filter;
        if (has_filter) {
            if (filter_found) {
                (void) snprintf(report.device_id, sizeof(report.device_id), "%lld", (long long) device_id);
            } else {
                cmaper_history_copy_string(report.device_id, sizeof(report.device_id), config->history.device_id);
            }
        }

        if (session_ref.found) {
            rc = cmaper_history_query_posture_counters(db, session_ref.id, device_id, &report.counters);
            if (rc != CMAPER_OK) {
                cmaper_history_posture_report_dispose(&report);
                return rc;
            }

            rc = cmaper_history_query_previous_completed_session(db, session_ref.id, &previous_ref);
            if (rc != CMAPER_OK) {
                cmaper_history_posture_report_dispose(&report);
                return rc;
            }
            if (previous_ref.found) {
                report.drift.has_previous = true;
                cmaper_history_copy_string(
                    report.drift.previous_session_id,
                    sizeof(report.drift.previous_session_id),
                    previous_ref.session_uid
                );

                rc = cmaper_history_query_posture_counters(
                    db,
                    previous_ref.id,
                    device_id,
                    &previous_counters
                );
                if (rc != CMAPER_OK) {
                    cmaper_history_posture_report_dispose(&report);
                    return rc;
                }

                report.drift.hosts_total_delta =
                    cmaper_history_delta_size(report.counters.hosts_total, previous_counters.hosts_total);
                report.drift.hosts_up_delta =
                    cmaper_history_delta_size(report.counters.hosts_up, previous_counters.hosts_up);
                report.drift.devices_total_delta =
                    cmaper_history_delta_size(report.counters.devices_total, previous_counters.devices_total);
                report.drift.open_tcp_ports_delta =
                    cmaper_history_delta_size(report.counters.open_tcp_ports, previous_counters.open_tcp_ports);
                report.drift.findings_total_delta =
                    cmaper_history_delta_size(report.counters.findings_total, previous_counters.findings_total);
                report.drift.findings_open_delta =
                    cmaper_history_delta_size(report.counters.findings_open, previous_counters.findings_open);
                report.drift.findings_high_or_worse_delta =
                    cmaper_history_delta_size(
                        report.counters.findings_high_or_worse,
                        previous_counters.findings_high_or_worse
                    );
                report.drift.management_surfaces_total_delta =
                    cmaper_history_delta_size(
                        report.counters.management_surfaces_total,
                        previous_counters.management_surfaces_total
                    );
                report.drift.hosts_with_management_surfaces_delta =
                    cmaper_history_delta_size(
                        report.counters.hosts_with_management_surfaces,
                        previous_counters.hosts_with_management_surfaces
                    );
                report.drift.risk_increased =
                    report.drift.findings_high_or_worse_delta > 0
                    || report.drift.management_surfaces_total_delta > 0
                    || report.drift.findings_open_delta > 0;
            }

            rc = cmaper_history_alerts_build_for_posture(&report);
            if (rc != CMAPER_OK) {
                cmaper_history_posture_report_dispose(&report);
                return rc;
            }
        }
    } else {
        report.db_available = false;
        cmaper_history_copy_string(report.session_id, sizeof(report.session_id), config->history.session_id);
        report.has_device_filter = config->history.device_id != NULL;
        if (config->history.device_id != NULL) {
            cmaper_history_copy_string(report.device_id, sizeof(report.device_id), config->history.device_id);
        }
    }

    cmaper_history_render_posture(report_stream, render_options, &report);
    cmaper_history_posture_report_dispose(&report);
    return CMAPER_OK;
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
