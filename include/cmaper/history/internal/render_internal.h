#ifndef CMAPER_HISTORY_INTERNAL_RENDER_INTERNAL_H
#define CMAPER_HISTORY_INTERNAL_RENDER_INTERNAL_H

#include <stdbool.h>
#include <stdio.h>

#include "cmaper/history/render.h"

cmaper_output_format_t cmaper_history_render_format(const cmaper_history_render_options_t *options);
cmaper_output_view_t cmaper_history_render_view(const cmaper_history_render_options_t *options);
bool cmaper_history_render_use_ansi(const cmaper_history_render_options_t *options);

size_t cmaper_history_render_count_for_view(
    size_t total,
    cmaper_output_view_t view,
    size_t compact_limit
);

void cmaper_history_render_heading(FILE *stream, bool use_ansi, const char *title);

void cmaper_history_json_string(FILE *stream, const char *value);

void cmaper_history_render_reason_mask_text(FILE *stream, unsigned int mask);
void cmaper_history_render_reason_mask_json(FILE *stream, unsigned int mask);

void cmaper_history_render_alerts_text(
    FILE *stream,
    const cmaper_history_alert_t *alerts,
    size_t alert_count
);

void cmaper_history_render_alerts_json(
    FILE *stream,
    const cmaper_history_alert_t *alerts,
    size_t alert_count
);

#endif
