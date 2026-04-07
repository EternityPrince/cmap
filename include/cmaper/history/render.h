#ifndef CMAPER_HISTORY_RENDER_H
#define CMAPER_HISTORY_RENDER_H

#include <stdbool.h>
#include <stdio.h>

#include "cmaper/cli/config.h"
#include "cmaper/history/domain.h"

typedef struct {
  cmaper_output_format_t format;
  cmaper_output_view_t view;
  bool use_ansi;
} cmaper_history_render_options_t;

void cmaper_history_render_sessions(
    FILE *stream, const cmaper_history_render_options_t *options,
    const cmaper_history_sessions_report_t *report);

void cmaper_history_render_session(
    FILE *stream, const cmaper_history_render_options_t *options,
    const cmaper_history_session_report_t *report);

void cmaper_history_render_devices(
    FILE *stream, const cmaper_history_render_options_t *options,
    const cmaper_history_devices_report_t *report);

void cmaper_history_render_device(
    FILE *stream, const cmaper_history_render_options_t *options,
    const cmaper_history_device_report_t *report);

void cmaper_history_render_timeline(
    FILE *stream, const cmaper_history_render_options_t *options,
    const cmaper_history_timeline_report_t *report);

void cmaper_history_render_diff(FILE *stream,
                                const cmaper_history_render_options_t *options,
                                const cmaper_history_diff_report_t *report,
                                bool summary_only);

void cmaper_history_render_posture(
    FILE *stream, const cmaper_history_render_options_t *options,
    const cmaper_history_posture_report_t *report);

#endif
