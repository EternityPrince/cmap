#include "cmaper/history/internal/service_internal.h"

#include <stdio.h>

static long cmaper_history_delta_size(size_t current_value, size_t previous_value) {
    if (current_value >= previous_value) {
        return (long) (current_value - previous_value);
    }
    return -((long) (previous_value - current_value));
}

cmaper_err_t cmaper_history_run_posture(
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
