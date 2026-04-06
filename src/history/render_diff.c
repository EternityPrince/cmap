#include "cmaper/history/internal/render_internal.h"

#include <stdio.h>

void cmaper_history_render_diff(
    FILE *stream,
    const cmaper_history_render_options_t *options,
    const cmaper_history_diff_report_t *report,
    bool summary_only
) {
    size_t i;
    size_t shown_changed_count;
    bool details_enabled;
    cmaper_output_format_t format;
    cmaper_output_view_t view;
    bool use_ansi;

    if (stream == NULL || report == NULL) {
        return;
    }

    format = cmaper_history_render_format(options);
    view = cmaper_history_render_view(options);
    use_ansi = cmaper_history_render_use_ansi(options);
    details_enabled = !summary_only && view == CMAPER_OUTPUT_VIEW_FULL;
    shown_changed_count = details_enabled
        ? report->changed_host_count
        : cmaper_history_render_count_for_view(report->changed_host_count, view, 12U);

    if (format == CMAPER_OUTPUT_FORMAT_JSON) {
        fputs("{\"report\":\"diff\",", stream);
        fprintf(
            stream,
            "\"view\":\"%s\",\"db_available\":%s,\"from_found\":%s,\"to_found\":%s,\"summary_only\":%s,\"details_enabled\":%s,",
            cmaper_output_view_name(view),
            report->db_available ? "true" : "false",
            report->from_found ? "true" : "false",
            report->to_found ? "true" : "false",
            summary_only ? "true" : "false",
            details_enabled ? "true" : "false"
        );
        fputs("\"from_session_id\":", stream);
        cmaper_history_json_string(stream, report->from_session_id);
        fputs(",\"to_session_id\":", stream);
        cmaper_history_json_string(stream, report->to_session_id);
        fprintf(
            stream,
            ",\"summary\":{\"hosts_from\":%zu,\"hosts_to\":%zu,\"hosts_added\":%zu,\"hosts_removed\":%zu,\"hosts_changed\":%zu,\"hosts_moved\":%zu,\"hosts_unchanged\":%zu,"
            "\"ports_added\":%zu,\"ports_removed\":%zu,\"fingerprints_added\":%zu,\"fingerprints_removed\":%zu,"
            "\"findings_opened\":%zu,\"findings_resolved\":%zu,\"findings_high_opened\":%zu,"
            "\"management_added\":%zu,\"management_removed\":%zu}",
            report->summary.hosts_from,
            report->summary.hosts_to,
            report->summary.hosts_added,
            report->summary.hosts_removed,
            report->summary.hosts_changed,
            report->summary.hosts_moved,
            report->summary.hosts_unchanged,
            report->summary.ports_added,
            report->summary.ports_removed,
            report->summary.fingerprints_added,
            report->summary.fingerprints_removed,
            report->summary.findings_opened,
            report->summary.findings_resolved,
            report->summary.findings_high_opened,
            report->summary.management_added,
            report->summary.management_removed
        );
        fputc(',', stream);
        cmaper_history_render_alerts_json(stream, report->alerts, report->alert_count);
        fputs(",\"changed_hosts\":[", stream);
        if (!summary_only) {
            for (i = 0; i < shown_changed_count; ++i) {
                const cmaper_history_changed_host_t *row = &report->changed_hosts[i];
                if (i > 0U) {
                    fputc(',', stream);
                }
                fputc('{', stream);
                fputs("\"host_key\":", stream);
                cmaper_history_json_string(stream, row->host_key);
                fputs(",\"match_strategy\":", stream);
                cmaper_history_json_string(stream, row->match_strategy);
                fputs(",\"from_ip\":", stream);
                cmaper_history_json_string(stream, row->from_ip);
                fputs(",\"to_ip\":", stream);
                cmaper_history_json_string(stream, row->to_ip);
                fputs(",\"from_status\":", stream);
                cmaper_history_json_string(stream, row->from_status);
                fputs(",\"to_status\":", stream);
                cmaper_history_json_string(stream, row->to_status);
                fputs(",\"reasons\":", stream);
                cmaper_history_render_reason_mask_json(stream, row->reason_mask);
                fprintf(
                    stream,
                    ",\"ports_added\":%zu,\"ports_removed\":%zu,\"fingerprints_added\":%zu,\"fingerprints_removed\":%zu,"
                    "\"findings_opened\":%zu,\"findings_resolved\":%zu,\"findings_high_opened\":%zu,"
                    "\"management_added\":%zu,\"management_removed\":%zu,\"risky_surfaces_added\":%zu",
                    row->ports_added,
                    row->ports_removed,
                    row->fingerprints_added,
                    row->fingerprints_removed,
                    row->findings_opened,
                    row->findings_resolved,
                    row->findings_high_opened,
                    row->management_added,
                    row->management_removed,
                    row->risky_surfaces_added
                );
                fputc('}', stream);
            }
        }
        fputs("]}\n", stream);
        return;
    }

    if (format == CMAPER_OUTPUT_FORMAT_MARKDOWN) {
        if (!report->db_available) {
            fputs("# Diff\n\nNo history database found.\n", stream);
            return;
        }
        if (!report->from_found || !report->to_found) {
            fprintf(
                stream,
                "# Diff\n\nSession not found: from `%s` (%s), to `%s` (%s)\n",
                report->from_session_id,
                report->from_found ? "found" : "missing",
                report->to_session_id,
                report->to_found ? "found" : "missing"
            );
            return;
        }

        fprintf(
            stream,
            "# Diff `%s` -> `%s`\n\n- Hosts from/to: **%zu / %zu**\n- Added/Removed/Changed/Moved: **%zu / %zu / %zu / %zu**\n- Ports +/−: **%zu / %zu**\n- Findings opened/resolved/high-opened: **%zu / %zu / %zu**\n- Management +/−: **%zu / %zu**\n\n",
            report->from_session_id,
            report->to_session_id,
            report->summary.hosts_from,
            report->summary.hosts_to,
            report->summary.hosts_added,
            report->summary.hosts_removed,
            report->summary.hosts_changed,
            report->summary.hosts_moved,
            report->summary.ports_added,
            report->summary.ports_removed,
            report->summary.findings_opened,
            report->summary.findings_resolved,
            report->summary.findings_high_opened,
            report->summary.management_added,
            report->summary.management_removed
        );

        fputs("## Alerts\n\n", stream);
        for (i = 0; i < report->alert_count; ++i) {
            fprintf(
                stream,
                "- **%s** %s (`%s`)%s%s\n",
                report->alerts[i].severity,
                report->alerts[i].title,
                report->alerts[i].code,
                report->alerts[i].host_key[0] != '\0' ? " host=" : "",
                report->alerts[i].host_key[0] != '\0' ? report->alerts[i].host_key : ""
            );
        }
        if (report->alert_count == 0) {
            fputs("- none\n", stream);
        }

        if (!summary_only && shown_changed_count > 0) {
            fputs("\n## Changed hosts\n\n| Host | Reasons | Ports +/− | Findings +/−/high+ | Mgmt +/− |\n", stream);
            fputs("|---|---|---:|---:|---:|\n", stream);
            for (i = 0; i < shown_changed_count; ++i) {
                const cmaper_history_changed_host_t *row = &report->changed_hosts[i];
                fprintf(stream, "| %s | ", row->host_key);
                cmaper_history_render_reason_mask_text(stream, row->reason_mask);
                fprintf(
                    stream,
                    " | %zu/%zu | %zu/%zu/%zu | %zu/%zu |\n",
                    row->ports_added,
                    row->ports_removed,
                    row->findings_opened,
                    row->findings_resolved,
                    row->findings_high_opened,
                    row->management_added,
                    row->management_removed
                );
            }
            if (!details_enabled && shown_changed_count < report->changed_host_count) {
                fprintf(
                    stream,
                    "\n_Compact view: showing first %zu of %zu changed hosts._\n",
                    shown_changed_count,
                    report->changed_host_count
                );
            }
        }
        return;
    }

    if (!report->db_available) {
        fputs("Diff: no history database found.\n", stream);
        return;
    }
    if (!report->from_found || !report->to_found) {
        fprintf(
            stream,
            "Diff: session not found (from=%s found=%s, to=%s found=%s)\n",
            report->from_session_id,
            report->from_found ? "yes" : "no",
            report->to_session_id,
            report->to_found ? "yes" : "no"
        );
        return;
    }

    cmaper_history_render_heading(stream, use_ansi, "Diff");
    fprintf(
        stream,
        "Summary: %s -> %s\n  hosts from/to=%zu/%zu added=%zu removed=%zu changed=%zu moved=%zu unchanged=%zu\n"
        "  ports +%zu/-%zu fingerprints +%zu/-%zu findings opened/resolved/high-opened=%zu/%zu/%zu management +%zu/-%zu\n",
        report->from_session_id,
        report->to_session_id,
        report->summary.hosts_from,
        report->summary.hosts_to,
        report->summary.hosts_added,
        report->summary.hosts_removed,
        report->summary.hosts_changed,
        report->summary.hosts_moved,
        report->summary.hosts_unchanged,
        report->summary.ports_added,
        report->summary.ports_removed,
        report->summary.fingerprints_added,
        report->summary.fingerprints_removed,
        report->summary.findings_opened,
        report->summary.findings_resolved,
        report->summary.findings_high_opened,
        report->summary.management_added,
        report->summary.management_removed
    );

    cmaper_history_render_alerts_text(stream, report->alerts, report->alert_count);

    if (!summary_only) {
        fprintf(stream, "Changed hosts: %zu\n", report->changed_host_count);
        for (i = 0; i < shown_changed_count; ++i) {
            const cmaper_history_changed_host_t *row = &report->changed_hosts[i];
            fprintf(stream, "  %s reasons=", row->host_key);
            cmaper_history_render_reason_mask_text(stream, row->reason_mask);
            fprintf(
                stream,
                " ports +%zu/-%zu fp +%zu/-%zu findings +%zu/-%zu high+%zu mgmt +%zu/-%zu\n",
                row->ports_added,
                row->ports_removed,
                row->fingerprints_added,
                row->fingerprints_removed,
                row->findings_opened,
                row->findings_resolved,
                row->findings_high_opened,
                row->management_added,
                row->management_removed
            );
        }
        if (!details_enabled && shown_changed_count < report->changed_host_count) {
            fprintf(
                stream,
                "  ... compact view: showing %zu of %zu changed hosts (use --view full)\n",
                shown_changed_count,
                report->changed_host_count
            );
        }
    }
}

