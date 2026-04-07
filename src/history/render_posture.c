#include "cmaper/history/internal/render_internal.h"

#include <stdio.h>

static const char *cmaper_history_posture_risk_level(
    const cmaper_history_posture_report_t *report) {
  if (report == NULL) {
    return "info";
  }
  if (report->counters.findings_high_or_worse > 0U ||
      (report->drift.has_previous &&
       report->drift.findings_high_or_worse_delta > 0L)) {
    return "critical";
  }
  if (report->drift.risk_increased || report->counters.findings_open > 0U ||
      report->counters.management_surfaces_total > 0U) {
    return "warn";
  }
  return "ok";
}

void cmaper_history_render_posture(
    FILE *stream, const cmaper_history_render_options_t *options,
    const cmaper_history_posture_report_t *report) {
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
    fprintf(stream,
            "\"view\":\"%s\",\"db_available\":%s,\"session_found\":%s,\"has_"
            "device_filter\":%s,",
            cmaper_output_view_name(view),
            report->db_available ? "true" : "false",
            report->session_found ? "true" : "false",
            report->has_device_filter ? "true" : "false");
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
    fprintf(stream,
            ",\"counters\":{\"hosts_total\":%zu,\"hosts_up\":%zu,\"devices_"
            "total\":%zu,\"open_tcp_ports\":%zu,"
            "\"findings_total\":%zu,\"findings_open\":%zu,\"findings_high_or_"
            "worse\":%zu,"
            "\"management_surfaces_total\":%zu,\"hosts_with_management_"
            "surfaces\":%zu},",
            report->counters.hosts_total, report->counters.hosts_up,
            report->counters.devices_total, report->counters.open_tcp_ports,
            report->counters.findings_total, report->counters.findings_open,
            report->counters.findings_high_or_worse,
            report->counters.management_surfaces_total,
            report->counters.hosts_with_management_surfaces);
    fprintf(stream, "\"drift\":{\"has_previous\":%s,\"previous_session_id\":",
            report->drift.has_previous ? "true" : "false");
    cmaper_history_json_string(stream, report->drift.previous_session_id);
    fprintf(
        stream,
        ",\"hosts_total_delta\":%ld,\"hosts_up_delta\":%ld,\"devices_total_"
        "delta\":%ld,"
        "\"open_tcp_ports_delta\":%ld,\"findings_total_delta\":%ld,\"findings_"
        "open_delta\":%ld,"
        "\"findings_high_or_worse_delta\":%ld,\"management_surfaces_total_"
        "delta\":%ld,"
        "\"hosts_with_management_surfaces_delta\":%ld,\"risk_increased\":%s},",
        report->drift.hosts_total_delta, report->drift.hosts_up_delta,
        report->drift.devices_total_delta, report->drift.open_tcp_ports_delta,
        report->drift.findings_total_delta, report->drift.findings_open_delta,
        report->drift.findings_high_or_worse_delta,
        report->drift.management_surfaces_total_delta,
        report->drift.hosts_with_management_surfaces_delta,
        report->drift.risk_increased ? "true" : "false");
    cmaper_history_render_alerts_json(stream, report->alerts,
                                      report->alert_count);
    fputs("}\n", stream);
    return;
  }

  if (format == CMAPER_OUTPUT_FORMAT_MARKDOWN) {
    fputs("# Posture\n\n## Context\n\n", stream);
    fprintf(stream, "- Database: **%s**\n",
            report->db_available ? "ready" : "missing");
    fprintf(stream, "- Session: `%s`\n", report->session_id);
    fprintf(stream, "- Session status: **%s**\n", report->session_status);
    fprintf(stream, "- Device filter: %s\n",
            report->has_device_filter ? "enabled" : "not set");
    if (report->has_device_filter) {
      fprintf(stream, "- Device id: `%s`\n", report->device_id);
    }
    fprintf(stream, "- Started: `%s`\n", report->started_at);
    fprintf(stream, "- Completed: `%s`\n", report->completed_at);

    if (!report->db_available) {
      fputs("\n## Notes\n\nNo history database found.\n", stream);
      return;
    }
    if (!report->session_found) {
      fputs("\n## Notes\n\nSession was not found in history.\n", stream);
      return;
    }

    fputs("\n## Key Takeaways\n\n", stream);
    fprintf(stream, "- **Risk:** **%s**\n",
            report->counters.findings_high_or_worse > 0U
                ? "CRITICAL"
                : ((report->drift.risk_increased ||
                    report->counters.findings_open > 0U ||
                    report->counters.management_surfaces_total > 0U)
                       ? "WARN"
                       : "OK"));
    fprintf(stream, "- Open findings: **%zu** (high/critical **%zu**)\n",
            report->counters.findings_open,
            report->counters.findings_high_or_worse);
    fprintf(stream, "- Management surfaces: **%zu** across **%zu** hosts\n",
            report->counters.management_surfaces_total,
            report->counters.hosts_with_management_surfaces);
    if (report->drift.has_previous) {
      fprintf(stream,
              "- Drift vs `%s`: open findings **%+ld**, high/critical "
              "**%+ld**, surfaces **%+ld**\n",
              report->drift.previous_session_id,
              report->drift.findings_open_delta,
              report->drift.findings_high_or_worse_delta,
              report->drift.management_surfaces_total_delta);
    } else {
      fputs("- Drift baseline: previous completed session not found.\n",
            stream);
    }

    fputs("\n## Details\n\n### Counters\n\n| Metric | Value |\n|---|---:|\n",
          stream);
    fprintf(stream, "| Hosts total | %zu |\n", report->counters.hosts_total);
    fprintf(stream, "| Hosts up | %zu |\n", report->counters.hosts_up);
    fprintf(stream, "| Devices | %zu |\n", report->counters.devices_total);
    fprintf(stream, "| Open TCP ports | %zu |\n",
            report->counters.open_tcp_ports);
    fprintf(stream, "| Findings total | %zu |\n",
            report->counters.findings_total);
    fprintf(stream, "| Findings open | %zu |\n",
            report->counters.findings_open);
    fprintf(stream, "| Findings high/critical | %zu |\n",
            report->counters.findings_high_or_worse);
    fprintf(stream, "| Management surfaces | %zu |\n",
            report->counters.management_surfaces_total);
    fprintf(stream, "| Hosts with management surfaces | %zu |\n",
            report->counters.hosts_with_management_surfaces);

    fputs("\n### Drift\n\n", stream);
    if (report->drift.has_previous) {
      fprintf(stream, "- Previous completed session: `%s`\n",
              report->drift.previous_session_id);
      fprintf(stream, "- Hosts total delta: **%+ld**\n",
              report->drift.hosts_total_delta);
      fprintf(stream, "- Hosts up delta: **%+ld**\n",
              report->drift.hosts_up_delta);
      fprintf(stream, "- Devices delta: **%+ld**\n",
              report->drift.devices_total_delta);
      fprintf(stream, "- Open TCP delta: **%+ld**\n",
              report->drift.open_tcp_ports_delta);
      fprintf(stream, "- Findings total delta: **%+ld**\n",
              report->drift.findings_total_delta);
      fprintf(stream, "- Findings open delta: **%+ld**\n",
              report->drift.findings_open_delta);
      fprintf(stream, "- Findings high/critical delta: **%+ld**\n",
              report->drift.findings_high_or_worse_delta);
      fprintf(stream, "- Management surfaces delta: **%+ld**\n",
              report->drift.management_surfaces_total_delta);
      fprintf(stream, "- Hosts with management surfaces delta: **%+ld**\n",
              report->drift.hosts_with_management_surfaces_delta);
      fprintf(stream, "- Risk increased: **%s**\n",
              report->drift.risk_increased ? "yes" : "no");
    } else {
      fputs("- Previous completed session not found.\n", stream);
    }

    fputs("\n### Alerts\n\n", stream);
    if (report->alert_count == 0U) {
      fputs("- none\n", stream);
    }
    for (size_t j = 0U; j < report->alert_count; ++j) {
      fprintf(stream, "- **%s** %s (`%s`)\n", report->alerts[j].severity,
              report->alerts[j].title, report->alerts[j].code);
    }

    fputs("\n## Next Steps\n\n", stream);
    if (report->counters.findings_high_or_worse > 0U) {
      fputs("1. Prioritize remediation for open high/critical findings.\n",
            stream);
      fputs("2. Re-run posture after fixes to confirm high-risk reduction.\n",
            stream);
    } else if (report->drift.risk_increased ||
               report->counters.management_surfaces_total > 0U) {
      fputs("1. Investigate why risk counters increased versus the previous "
            "session.\n",
            stream);
      fputs("2. Reduce exposed management surfaces where possible.\n", stream);
    } else {
      fputs("1. Keep this posture snapshot as baseline for future drift "
            "checks.\n",
            stream);
      fputs("2. Continue routine scanning to maintain trend visibility.\n",
            stream);
    }
    return;
  }

  cmaper_history_render_heading(stream, use_ansi, "Posture");
  cmaper_history_render_section(stream, use_ansi, "Context");
  cmaper_history_render_key_value(stream, "Database",
                                  report->db_available ? "ready" : "missing");
  cmaper_history_render_key_value(stream, "Session", report->session_id);
  cmaper_history_render_key_value(stream, "Session status",
                                  report->session_status);
  cmaper_history_render_key_value(stream, "Device filter",
                                  report->has_device_filter ? "enabled"
                                                            : "not set");
  if (report->has_device_filter) {
    cmaper_history_render_key_value(stream, "Device id", report->device_id);
  }
  cmaper_history_render_key_value(stream, "Started", report->started_at);
  cmaper_history_render_key_value(stream, "Completed", report->completed_at);

  if (!report->db_available) {
    cmaper_history_render_section(stream, use_ansi, "Notes");
    fputs("  No history database found.\n", stream);
    return;
  }
  if (!report->session_found) {
    cmaper_history_render_section(stream, use_ansi, "Notes");
    fputs("  Session was not found in history.\n", stream);
    return;
  }

  cmaper_history_render_section(stream, use_ansi, "Key Takeaways");
  cmaper_history_render_risk(
      stream, use_ansi, cmaper_history_posture_risk_level(report),
      report->counters.findings_high_or_worse > 0U
          ? "Open high/critical findings are currently present."
          : (report->drift.risk_increased
                 ? "Risk indicators increased versus the previous completed "
                   "session."
                 : ((report->counters.findings_open > 0U ||
                     report->counters.management_surfaces_total > 0U)
                        ? "There are open findings or management exposures to "
                          "review."
                        : "No immediate high-risk signal in this posture "
                          "snapshot.")));
  fprintf(stream, "  Open findings: %zu (high/critical: %zu)\n",
          report->counters.findings_open,
          report->counters.findings_high_or_worse);
  fprintf(stream, "  Management surfaces: %zu across %zu hosts\n",
          report->counters.management_surfaces_total,
          report->counters.hosts_with_management_surfaces);

  cmaper_history_render_section(stream, use_ansi, "Details");
  fprintf(stream,
          "Counters: hosts total=%zu up=%zu devices=%zu open_tcp=%zu findings "
          "total=%zu open=%zu high=%zu surfaces=%zu hosts-with-surfaces=%zu\n",
          report->counters.hosts_total, report->counters.hosts_up,
          report->counters.devices_total, report->counters.open_tcp_ports,
          report->counters.findings_total, report->counters.findings_open,
          report->counters.findings_high_or_worse,
          report->counters.management_surfaces_total,
          report->counters.hosts_with_management_surfaces);

  if (report->drift.has_previous) {
    fprintf(stream, "Drift vs %s:\n", report->drift.previous_session_id);
    cmaper_history_render_key_signed(stream, use_ansi, "  Hosts total delta",
                                     report->drift.hosts_total_delta);
    cmaper_history_render_key_signed(stream, use_ansi, "  Hosts up delta",
                                     report->drift.hosts_up_delta);
    cmaper_history_render_key_signed(stream, use_ansi, "  Devices delta",
                                     report->drift.devices_total_delta);
    cmaper_history_render_key_signed(stream, use_ansi, "  Open TCP delta",
                                     report->drift.open_tcp_ports_delta);
    cmaper_history_render_key_signed(stream, use_ansi, "  Findings total delta",
                                     report->drift.findings_total_delta);
    cmaper_history_render_key_signed(stream, use_ansi, "  Findings open delta",
                                     report->drift.findings_open_delta);
    cmaper_history_render_key_signed(
        stream, use_ansi, "  Findings high/critical delta",
        report->drift.findings_high_or_worse_delta);
    cmaper_history_render_key_signed(
        stream, use_ansi, "  Management surfaces delta",
        report->drift.management_surfaces_total_delta);
    cmaper_history_render_key_signed(
        stream, use_ansi, "  Hosts with management surfaces delta",
        report->drift.hosts_with_management_surfaces_delta);
    cmaper_history_render_key_value(stream, "  Risk increased",
                                    report->drift.risk_increased ? "yes"
                                                                 : "no");
  } else {
    fputs("Drift: previous completed session not found.\n", stream);
  }

  fputs("Alerts\n", stream);
  cmaper_history_render_alerts_text(stream, use_ansi, report->alerts,
                                    report->alert_count);

  cmaper_history_render_section(stream, use_ansi, "Next Steps");
  if (report->counters.findings_high_or_worse > 0U) {
    fputs("  1. Prioritize remediation for open high/critical findings.\n",
          stream);
    fputs("  2. Re-run posture after fixes to confirm high-risk reduction.\n",
          stream);
  } else if (report->drift.risk_increased ||
             report->counters.management_surfaces_total > 0U) {
    fputs("  1. Investigate why risk counters increased versus the previous "
          "session.\n",
          stream);
    fputs("  2. Reduce exposed management surfaces where possible.\n", stream);
  } else {
    fputs("  1. Keep this posture snapshot as baseline for future drift "
          "checks.\n",
          stream);
    fputs("  2. Continue routine scanning to maintain trend visibility.\n",
          stream);
  }
}
