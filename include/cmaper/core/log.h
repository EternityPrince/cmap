#ifndef CMAPER_CORE_LOG_H
#define CMAPER_CORE_LOG_H

#include <stdbool.h>
#include <stdio.h>

typedef enum {
    CMAPER_LOG_QUIET = 0,
    CMAPER_LOG_PHASE,
    CMAPER_LOG_INFO,
    CMAPER_LOG_WAIT,
    CMAPER_LOG_OK,
    CMAPER_LOG_WARN,
    CMAPER_LOG_FAIL
} cmaper_log_level_t;

typedef struct {
    FILE *stream;
    cmaper_log_level_t level;
    bool use_color;
} cmaper_logger_t;

void cmaper_log_init(cmaper_logger_t *logger, FILE *stream, cmaper_log_level_t level);
void cmaper_log_set_level(cmaper_logger_t *logger, cmaper_log_level_t level);
const char *cmaper_log_level_name(cmaper_log_level_t level);
void cmaper_log(cmaper_logger_t *logger, cmaper_log_level_t level, const char *fmt, ...);

#endif
