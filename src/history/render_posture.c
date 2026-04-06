#include "cmaper/history/internal/render_internal.h"

#include <stdio.h>

void cmaper_history_render_posture(
    FILE *stream,
    const cmaper_history_render_options_t *options,
    const cmaper_history_posture_report_t *report
) {
    cmaper_output_format_t format;
    cmaper_output_view_t view;
    bool use_ansi;

    if (stream == NULL || report == NULL) {
        return;
    }

    format = cmaper_history_render_format(options);
    view = cmaper_history_render_view(options);
    use_ansi = cmaper_history_render_use_ansi(options);

    if (format == CMAPER_OUTPUT_FORMAT_JSON) {
        fputs("{\"report\":\"posture\",", stream);
        fprintf(
            stream,
            "\"view\":\"%s\",\"db_available\":%s,\"session_found\":%s,\"has_device_filter\":%s,",
            cmaper_output_view_name(view),
            report->db_available ? "true" : "false",
            report->session_found ? "true" : "false",
            report->has_device_filter ? "true" : "false"
        );
        fputs("\"session_id\":", stream);
        cmaper_history_json_string(stream, report->session_id);
        fputs(",\"device_id\":", stream);
        cmaper_history_json_string(stream, report->device_id);
        fputs(",\"session_status\":", stream);
        cmaper_history_json_string(stream, report->session_status);
        fputs(",\"started_at\":", stream);
        cmaper_history_json_string(stream, report->started_at);
        fputs(",\"completed_at\":", stream);
        cmaper_history_json_string(stream, report->completed_at);
        fprintf(
            stream,
            ",\"counters\":{\"hosts_total\":%zu,\"hosts_up\":%zu,\"devices_total\":%zu,\"open_tcp_ports\":%zu,"
            "\"findings_total\":%zu,\"findings_open\":%zu,\"findings_high_or_worse\":%zu,"
            "\"management_surfaces_total\":%zu,\"hosts_with_management_surfaces\":%zu},",
            report->counters.hosts_total,
            report->counters.hosts_up,
            report->counters.devices_total,
            report->counters.open_tcp_ports,
            report->counters.findings_total,
            report->counters.findings_open,
            report->counters.findings_high_or_worse,
            report->counters.management_surfaces_total,
            report->counters.hosts_with_management_surfaces
        );
        fprintf(
            stream,
            "\"drift\":{\"has_previous\":%s,\"previous_session_id\":",
            report->drift.has_previous ? "true" : "false"
        );
        cmaper_history_json_string(stream, report->drift.previous_session_id);
        fprintf(
            stream,
            ",\"hosts_total_delta\":%ld,\"hosts_up_delta\":%ld,\"devices_total_delta\":%ld,"
            "\"open_tcp_ports_delta\":%ld,\"findings_total_delta\":%ld,\"findings_open_delta\":%ld,"
            "\"findings_high_or_worse_delta\":%ld,\"management_surfaces_total_delta\":%ld,"
            "\"hosts_with_management_surfaces_delta\":%ld,\"risk_increased\":%s},",
            report->drift.hosts_total_delta,
            report->drift.hosts_up_delta,
            report->drift.devices_total_delta,
            report->drift.open_tcp_ports_delta,
            report->drift.findings_total_delta,
            report->drift.findings_open_delta,
            report->drift.findings_high_or_worse_delta,
            report->drift.management_surfaces_total_delta,
            report->drift.hosts_with_management_surfaces_delta,
            report->drift.risk_increased ? "true" : "false"
        );
        cmaper_history_render_alerts_json(stream, report->alerts, report->alert_count);
        fputs("}\n", stream);
        return;
    }

    if (format == CMAPER_OUTPUT_FORMAT_MARKDOWN) {
        if (!report->db_available) {
            fputs("# Posture\n\nNo history database found.\n", stream);
            return;
        }
        if (!report->session_found) {
            fprintf(stream, "# Posture\n\nSession `%s` not found.\n", report->session_id);
            return;
        }

        fprintf(
            stream,
            "# Posture `%s`%s%s\n\n- Status: **%s**\n- Hosts total/up: **%zu / %zu**\n- Devices: **%zu**\n- Open TCP ports: **%zu**\n- Findings total/open/high: **%zu / %zu / %zu**\n- Management surfaces: **%zu** on **%zu** hosts\n\n",
            report->session_id,
            report->has_device_filter ? " (device: `" : "",
            report->has_device_filter ? report->device_id : "",
            report->session_status,
            report->counters.hosts_total,
            report->counters.hosts_up,
            report->counters.devices_total,
            report->counters.open_tcp_ports,
            report->counters.findings_total,
            report->counters.findings_open,
            report->counters.findings_high_or_worse,
            report->counters.management_surfaces_total,
            report->counters.hosts_with_management_surfaces
        );
        if (report->has_device_filter) {
            fputs("`)\n\n", stream);
        }

        if (report->drift.has_previous) {
            fprintf(
                stream,
                "## Drift vs `%s`\n\n- Hosts delta: **%+ld**\n- Open TCP delta: **%+ld**\n- Findings open delta: **%+ld**\n- Findings high delta: **%+ld**\n- Surfaces delta: **%+ld**\n- Risk increased: **%s**\n\n",
                report->drift.previous_session_id,
                report->drift.hosts_total_delta,
                report->drift.open_tcp_ports_delta,
                report->drift.findings_open_delta,
                report->drift.findings_high_or_worse_delta,
                report->drift.management_surfaces_total_delta,
                report->drift.risk_increased ? "yes" : "no"
            );
        } else {
            fputs("## Drift\n\nPrevious completed session not found.\n\n", stream);
        }

        fputs("## Alerts\n\n", stream);
        for (size_t j = 0; j < report->alert_count; ++j) {
            fprintf(
                stream,
                "- **%s** %s (`%s`)\n",
                report->alerts[j].severity,
                report->alerts[j].title,
                report->alerts[j].code
            );
        }
        if (report->alert_count == 0) {
            fputs("- none\n", stream);
        }
        return;
    }

    if (!report->db_available) {
        fputs("Posture: no history database found.\n", stream);
        return;
    }
    if (!report->session_found) {
        fprintf(stream, "Posture: session '%s' not found.\n", report->session_id);
        return;
    }

    cmaper_history_render_heading(stream, use_ansi, "Posture");
    fprintf(
        stream,
        "Summary: %s%s%s [%s]\n  hosts=%zu up=%zu devices=%zu open_tcp=%zu findings(total/open/high)=%zu/%zu/%zu surfaces=%zu hosts-with-surfaces=%zu\n",
        report->session_id,
        report->has_device_filter ? " device=" : "",
        report->has_device_filter ? report->device_id : "",
        report->session_status,
        report->counters.hosts_total,
        report->counters.hosts_up,
        report->counters.devices_total,
        report->counters.open_tcp_ports,
        report->counters.findings_total,
        report->counters.findings_open,
        report->counters.findings_high_or_worse,
        report->counters.management_surfaces_total,
        report->counters.hosts_with_management_surfaces
    );

    if (report->drift.has_previous) {
        fprintf(
            stream,
            "  drift vs %s: hosts=%+ld open_tcp=%+ld findings_open=%+ld findings_high=%+ld surfaces=%+ld risk_increased=%s\n",
            report->drift.previous_session_id,
            report->drift.hosts_total_delta,
            report->drift.open_tcp_ports_delta,
            report->drift.findings_open_delta,
            report->drift.findings_high_or_worse_delta,
            report->drift.management_surfaces_total_delta,
            report->drift.risk_increased ? "yes" : "no"
        );
    } else {
        fputs("  drift: previous completed session not found\n", stream);
    }

    cmaper_history_render_alerts_text(stream, report->alerts, report->alert_count);
}
