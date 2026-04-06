#include "cmaper/history/internal/render_internal.h"

#include <stdio.h>

static const char *cmaper_history_diff_risk_level(const cmaper_history_diff_report_t *report) {
    if (report == NULL) {
        return "info";
    }
    if (report->summary.findings_high_opened > 0U) {
        return "critical";
    }
    if (report->summary.findings_opened > report->summary.findings_resolved
        || report->summary.management_added > report->summary.management_removed
        || report->summary.hosts_added > 0U
        || report->summary.hosts_removed > 0U) {
        return "warn";
    }
    return "ok";
}

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
        fputs("# Diff\n\n## Context\n\n", stream);
        fprintf(stream, "- Database: **%s**\n", report->db_available ? "ready" : "missing");
        fprintf(stream, "- From session: `%s`\n", report->from_session_id);
        fprintf(stream, "- To session: `%s`\n", report->to_session_id);
        fprintf(stream, "- View: **%s**\n", cmaper_output_view_name(view));
        fprintf(stream, "- Summary-only mode: **%s**\n", summary_only ? "yes" : "no");

        if (!report->db_available) {
            fputs("\n## Notes\n\nNo history database found.\n", stream);
            return;
        }
        if (!report->from_found || !report->to_found) {
            fprintf(
                stream,
                "\n## Notes\n\nSession lookup failed: from `%s` (%s), to `%s` (%s)\n",
                report->from_session_id,
                report->from_found ? "found" : "missing",
                report->to_session_id,
                report->to_found ? "found" : "missing"
            );
            return;
        }

        fputs("\n## Key Takeaways\n\n", stream);
        fprintf(
            stream,
            "- **Risk:** **%s**\n",
            report->summary.findings_high_opened > 0U
                ? "CRITICAL"
                : ((report->summary.findings_opened > report->summary.findings_resolved
                    || report->summary.management_added > report->summary.management_removed)
                    ? "WARN"
                    : "OK")
        );
        if (report->summary.findings_high_opened > 0U) {
            fputs("- Compared to previous scan, new high-risk findings appeared.\n", stream);
        }
        fprintf(
            stream,
            "- Host changes: **%zu changed**, **%zu added**, **%zu removed**, **%zu moved**\n",
            report->summary.hosts_changed,
            report->summary.hosts_added,
            report->summary.hosts_removed,
            report->summary.hosts_moved
        );
        fprintf(
            stream,
            "- Findings drift: opened **%zu**, resolved **%zu**, high/critical opened **%zu**\n",
            report->summary.findings_opened,
            report->summary.findings_resolved,
            report->summary.findings_high_opened
        );
        fprintf(
            stream,
            "- Management surfaces: added **%zu**, removed **%zu**\n",
            report->summary.management_added,
            report->summary.management_removed
        );

        fputs("\n## Details\n\n### Alerts\n\n", stream);
        if (report->alert_count == 0U) {
            fputs("- none\n", stream);
        }
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

        if (!summary_only) {
            fputs(
                "\n### Changed Hosts\n\n| Host | Change reasons | Ports (+/-) | Findings (+/-/high+) | Mgmt (+/-) |\n"
                "|---|---|---:|---:|---:|\n",
                stream
            );
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
                cmaper_history_render_truncated_note(
                    stream,
                    true,
                    shown_changed_count,
                    report->changed_host_count,
                    "changed hosts"
                );
            }
        }

        fputs("\n## Next Steps\n\n", stream);
        if (report->summary.findings_high_opened > 0U) {
            fputs("1. Triage hosts with newly opened high/critical findings first.\n", stream);
            fputs("2. Re-run scan after mitigation to verify the high-risk count decreases.\n", stream);
        } else if (report->summary.findings_opened > report->summary.findings_resolved
            || report->summary.management_added > report->summary.management_removed) {
            fputs("1. Review why open findings or management exposure increased between sessions.\n", stream);
            fputs("2. Create a short remediation plan for the top changed hosts.\n", stream);
        } else {
            fputs("1. Use this diff as a baseline and continue regular drift monitoring.\n", stream);
            fputs("2. Spot-check a few changed hosts to confirm expected operational changes.\n", stream);
        }
        return;
    }

    cmaper_history_render_heading(stream, use_ansi, "Diff");
    cmaper_history_render_section(stream, use_ansi, "Context");
    cmaper_history_render_key_value(stream, "Database", report->db_available ? "ready" : "missing");
    cmaper_history_render_key_value(stream, "From session", report->from_session_id);
    cmaper_history_render_key_value(stream, "To session", report->to_session_id);
    cmaper_history_render_key_value(stream, "View", cmaper_output_view_name(view));
    cmaper_history_render_key_value(stream, "Summary-only mode", summary_only ? "yes" : "no");

    if (!report->db_available) {
        cmaper_history_render_section(stream, use_ansi, "Notes");
        fputs("  No history database found.\n", stream);
        return;
    }
    if (!report->from_found || !report->to_found) {
        cmaper_history_render_section(stream, use_ansi, "Notes");
        fprintf(
            stream,
            "  Session lookup failed: from=%s (%s), to=%s (%s)\n",
            report->from_session_id,
            report->from_found ? "found" : "missing",
            report->to_session_id,
            report->to_found ? "found" : "missing"
        );
        return;
    }

    cmaper_history_render_section(stream, use_ansi, "Key Takeaways");
    cmaper_history_render_risk(
        stream,
        use_ansi,
        cmaper_history_diff_risk_level(report),
        report->summary.findings_high_opened > 0U
            ? "Compared to previous scan, new high-risk findings appeared."
            : ((report->summary.findings_opened > report->summary.findings_resolved
                || report->summary.management_added > report->summary.management_removed)
                ? "Security drift indicates elevated risk compared to the previous session."
                : "No immediate high-risk drift signal in this diff.")
    );
    fprintf(
        stream,
        "  Host changes: changed=%zu added=%zu removed=%zu moved=%zu unchanged=%zu\n",
        report->summary.hosts_changed,
        report->summary.hosts_added,
        report->summary.hosts_removed,
        report->summary.hosts_moved,
        report->summary.hosts_unchanged
    );
    fprintf(
        stream,
        "  Findings drift: opened=%zu resolved=%zu high-opened=%zu\n",
        report->summary.findings_opened,
        report->summary.findings_resolved,
        report->summary.findings_high_opened
    );
    fprintf(
        stream,
        "  Management surfaces: +%zu/-%zu\n",
        report->summary.management_added,
        report->summary.management_removed
    );

    cmaper_history_render_section(stream, use_ansi, "Details");
    fputs("Alerts\n", stream);
    cmaper_history_render_alerts_text(stream, use_ansi, report->alerts, report->alert_count);

    if (!summary_only) {
        fprintf(stream, "Changed hosts (shown %zu):\n", shown_changed_count);
        if (shown_changed_count == 0U) {
            fputs("  - none\n", stream);
        }
        for (i = 0; i < shown_changed_count; ++i) {
            const cmaper_history_changed_host_t *row = &report->changed_hosts[i];
            fprintf(stream, "  - %s reasons=", row->host_key);
            cmaper_history_render_reason_mask_text(stream, row->reason_mask);
            fprintf(
                stream,
                " ports +%zu/-%zu findings +%zu/-%zu high+%zu mgmt +%zu/-%zu\n",
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
            cmaper_history_render_truncated_note(
                stream,
                false,
                shown_changed_count,
                report->changed_host_count,
                "changed hosts"
            );
        }
    }

    cmaper_history_render_section(stream, use_ansi, "Next Steps");
    if (report->summary.findings_high_opened > 0U) {
        fputs("  1. Triage hosts with newly opened high/critical findings first.\n", stream);
        fputs("  2. Re-run scan after mitigation to verify the high-risk count decreases.\n", stream);
    } else if (report->summary.findings_opened > report->summary.findings_resolved
        || report->summary.management_added > report->summary.management_removed) {
        fputs("  1. Review why open findings or management exposure increased between sessions.\n", stream);
        fputs("  2. Create a short remediation plan for the top changed hosts.\n", stream);
    } else {
        fputs("  1. Use this diff as a baseline and continue regular drift monitoring.\n", stream);
        fputs("  2. Spot-check a few changed hosts to confirm expected operational changes.\n", stream);
    }
}
