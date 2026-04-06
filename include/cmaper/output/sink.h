#ifndef CMAPER_OUTPUT_SINK_H
#define CMAPER_OUTPUT_SINK_H

#include <stdbool.h>
#include <stdio.h>

#include "cmaper/cli/config.h"
#include "cmaper/core/error.h"
#include "cmaper/core/log.h"

typedef struct {
    FILE *stream;
    bool owns_stream;
    bool capture_for_clipboard;
} cmaper_output_sink_t;

void cmaper_output_sink_init(cmaper_output_sink_t *sink);

cmaper_err_t cmaper_output_sink_open(
    cmaper_output_sink_t *sink,
    const cmaper_output_options_t *options,
    FILE *default_stream,
    cmaper_logger_t *logger
);

bool cmaper_output_sink_should_use_ansi(
    const cmaper_output_options_t *options,
    FILE *stream
);

cmaper_err_t cmaper_output_sink_finalize(
    cmaper_output_sink_t *sink,
    const cmaper_output_options_t *options,
    FILE *default_stream,
    cmaper_logger_t *logger
);

#endif
