#include "cmaper/history/internal/render_internal.h"

#include <stdio.h>

static const char *cmaper_history_timeline_risk_level(size_t findings_high,
                                                      size_t findings_open) {
  if (findings_high > 0U) {
    return "critical";
  }
  if (findings_open > 0U) {
    return "warn";
  }
  return "ok";
}

void cmaper_history_render_timeline(
    FILE *stream, const cmaper_history_render_options_t *options,
    const cmaper_history_timeline_report_t *report) {
  size_t i;
  size_t shown_count;
  cmaper_output_format_t format;
  cmaper_output_view_t view;
  bool use_ansi;

  if (stream == NULL || report == NULL) {
    return;
  }

  format = cmaper_history_render_format(options);
  view = cmaper_history_render_view(options);
  use_ansi = cmaper_history_render_use_ansi(options);
  shown_count = cmaper_history_render_count_for_view(report->count, view, 12U);

  if (format == CMAPER_OUTPUT_FORMAT_JSON) {
    fputs("{\"report\":\"timeline\",", stream);
    fprintf(stream,
            "\"view\":\"%s\",\"db_available\":%s,\"anchor_found\":%s,\"has_"
            "device_filter\":%s,\"limit\":%d,",
            cmaper_output_view_name(view),
            report->db_available ? "true" : "false",
            report->anchor_found ? "true" : "false",
            report->has_device_filter ? "true" : "false", report->limit);
    fputs("\"anchor_session_id\":", stream);
    cmaper_history_json_string(stream, report->anchor_session_id);
    fputs(",\"device_id\":", stream);
    cmaper_history_json_string(stream, report->device_id);
    fputs(",\"items\":[", stream);
    for (i = 0; i < shown_count; ++i) {
      const cmaper_history_timeline_row_t *row = &report->items[i];
      if (i > 0U) {
        fputc(',', stream);
      }
      fputc('{', stream);
      fputs("\"session_id\":", stream);
      cmaper_history_json_string(stream, row->session_id);
      fputs(",\"status\":", stream);
      cmaper_history_json_string(stream, row->status);
      fputs(",\"started_at\":", stream);
      cmaper_history_json_string(stream, row->started_at);
      fputs(",\"completed_at\":", stream);
      cmaper_history_json_string(stream, row->completed_at);
      fprintf(stream,
              ",\"hosts_total\":%zu,\"findings_open\":%zu,\"findings_high_or_"
              "worse\":%zu,\"management_surfaces\":%zu,\"device_present\":%s",
              row->hosts_total, row->findings_open, row->findings_high_or_worse,
              row->management_surfaces, row->device_present ? "true" : "false");
      fputs(",\"device_ip\":", stream);
      cmaper_history_json_string(stream, row->device_ip);
      fputs(",\"device_status\":", stream);
      cmaper_history_json_string(stream, row->device_status);
      fputc('}', stream);
    }
    fputs("]}\n", stream);
    return;
  }

  if (format == CMAPER_OUTPUT_FORMAT_MARKDOWN) {
    fputs("# Timeline\n\n## Context\n\n", stream);
    fprintf(stream, "- Database: **%s**\n",
            report->db_available ? "ready" : "missing");
    fprintf(stream, "- Anchor session: `%s`\n", report->anchor_session_id);
    fprintf(stream, "- Device filter: %s\n",
            report->has_device_filter ? "enabled" : "not set");
    if (report->has_device_filter) {
      fprintf(stream, "- Device id: `%s`\n", report->device_id);
    }
    fprintf(stream, "- Rows shown: **%zu**\n", shown_count);

    if (!report->db_available) {
      fputs("\n## Notes\n\nNo history database found.\n", stream);
      return;
    }
    if (!report->anchor_found) {
      fputs("\n## Notes\n\nAnchor session was not found.\n", stream);
      return;
    }

    fputs("\n## Key Takeaways\n\n", stream);
    if (shown_count == 0U) {
      fputs("- No timeline rows were returned for the selected scope.\n",
            stream);
    } else {
      const cmaper_history_timeline_row_t *anchor_row = &report->items[0];
      const cmaper_history_timeline_row_t *oldest_row =
          &report->items[shown_count - 1U];
      long open_delta =
          (long)anchor_row->findings_open - (long)oldest_row->findings_open;
      long high_delta = (long)anchor_row->findings_high_or_worse -
                        (long)oldest_row->findings_high_or_worse;
      long surfaces_delta = (long)anchor_row->management_surfaces -
                            (long)oldest_row->management_surfaces;

      fprintf(stream,
              "- **Risk:** **%s** for anchor session (open findings **%zu**, "
              "high/critical **%zu**)\n",
              anchor_row->findings_high_or_worse > 0U
                  ? "CRITICAL"
                  : (anchor_row->findings_open > 0U ? "WARN" : "OK"),
              anchor_row->findings_open, anchor_row->findings_high_or_worse);
      fprintf(stream,
              "- Drift from oldest shown row to anchor: open findings "
              "**%+ld**, high/critical **%+ld**, surfaces **%+ld**\n",
              open_delta, high_delta, surfaces_delta);
      if (report->has_device_filter) {
        fprintf(stream, "- Anchor device presence: **%s** (`%s`)\n",
                anchor_row->device_present ? "yes" : "no",
                anchor_row->device_ip);
      }
    }

    fputs("\n## Details\n\n| Session | Session status | Hosts | Open findings "
          "(high) | Surfaces | Device present | Device IP |\n"
          "|---|---|---:|---:|---:|---|---|\n",
          stream);
    for (i = 0; i < shown_count; ++i) {
      const cmaper_history_timeline_row_t *row = &report->items[i];
      fprintf(stream, "| %s | %s | %zu | %zu (%zu) | %zu | %s | %s |\n",
              row->session_id, row->status, row->hosts_total,
              row->findings_open, row->findings_high_or_worse,
              row->management_surfaces,
              report->has_device_filter ? (row->device_present ? "yes" : "no")
                                        : "-",
              report->has_device_filter ? row->device_ip : "-");
    }

    cmaper_history_render_truncated_note(stream, true, shown_count,
                                         report->count, "timeline rows");
    return;
  }

  cmaper_history_render_heading(stream, use_ansi, "Timeline");
  cmaper_history_render_section(stream, use_ansi, "Context");
  cmaper_history_render_key_value(stream, "Database",
                                  report->db_available ? "ready" : "missing");
  cmaper_history_render_key_value(stream, "Anchor session",
                                  report->anchor_session_id);
  cmaper_history_render_key_value(stream, "Device filter",
                                  report->has_device_filter ? "enabled"
                                                            : "not set");
  if (report->has_device_filter) {
    cmaper_history_render_key_value(stream, "Device id", report->device_id);
  }
  cmaper_history_render_key_size(stream, "Rows shown", shown_count);

  if (!report->db_available) {
    cmaper_history_render_section(stream, use_ansi, "Notes");
    fputs("  No history database found.\n", stream);
    return;
  }
  if (!report->anchor_found) {
    cmaper_history_render_section(stream, use_ansi, "Notes");
    fputs("  Anchor session was not found.\n", stream);
    return;
  }

  cmaper_history_render_section(stream, use_ansi, "Key Takeaways");
  if (shown_count == 0U) {
    fputs("  No timeline rows were returned for the selected scope.\n", stream);
  } else {
    const cmaper_history_timeline_row_t *anchor_row = &report->items[0];
    const cmaper_history_timeline_row_t *oldest_row =
        &report->items[shown_count - 1U];

    cmaper_history_render_risk(
        stream, use_ansi,
        cmaper_history_timeline_risk_level(anchor_row->findings_high_or_worse,
                                           anchor_row->findings_open),
        anchor_row->findings_high_or_worse > 0U
            ? "Anchor session has high/critical findings."
            : (anchor_row->findings_open > 0U
                   ? "Anchor session has open findings."
                   : "Anchor session has no open findings."));
    cmaper_history_render_key_signed(
        stream, use_ansi, "Open findings drift (anchor - oldest shown)",
        (long)anchor_row->findings_open - (long)oldest_row->findings_open);
    cmaper_history_render_key_signed(
        stream, use_ansi, "High/critical drift (anchor - oldest shown)",
        (long)anchor_row->findings_high_or_worse -
            (long)oldest_row->findings_high_or_worse);
    cmaper_history_render_key_signed(
        stream, use_ansi, "Management surfaces drift (anchor - oldest shown)",
        (long)anchor_row->management_surfaces -
            (long)oldest_row->management_surfaces);
    if (report->has_device_filter) {
      fprintf(stream, "  Anchor device presence: %s (ip=%s)\n",
              anchor_row->device_present ? "yes" : "no", anchor_row->device_ip);
    }
  }

  cmaper_history_render_section(stream, use_ansi, "Details");
  if (shown_count == 0U) {
    fputs("  No timeline rows to display.\n", stream);
  }
  for (i = 0; i < shown_count; ++i) {
    const cmaper_history_timeline_row_t *row = &report->items[i];
    fprintf(stream,
            "  - %s [%s] hosts=%zu open findings=%zu (high=%zu) surfaces=%zu\n",
            row->session_id, row->status, row->hosts_total, row->findings_open,
            row->findings_high_or_worse, row->management_surfaces);
    if (report->has_device_filter) {
      fprintf(stream, "    device present=%s ip=%s host-status=%s\n",
              row->device_present ? "yes" : "no", row->device_ip,
              row->device_status);
    }
  }

  cmaper_history_render_truncated_note(stream, false, shown_count,
                                       report->count, "timeline rows");
}
