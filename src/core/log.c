#include "cmaper/core/log.h"

#include <stdarg.h>

#include "cmaper/platform/terminal.h"

static cmaper_log_level_t cmaper_log_level_clamp(cmaper_log_level_t level) {
  if (level < CMAPER_LOG_QUIET) {
    return CMAPER_LOG_QUIET;
  }

  if (level > CMAPER_LOG_FAIL) {
    return CMAPER_LOG_FAIL;
  }

  return level;
}

static const char *cmaper_log_level_color(cmaper_log_level_t level) {
  switch (level) {
  case CMAPER_LOG_PHASE:
    return "\033[34m";
  case CMAPER_LOG_INFO:
    return "\033[36m";
  case CMAPER_LOG_WAIT:
    return "\033[35m";
  case CMAPER_LOG_OK:
    return "\033[32m";
  case CMAPER_LOG_WARN:
    return "\033[33m";
  case CMAPER_LOG_FAIL:
    return "\033[31m";
  case CMAPER_LOG_QUIET:
    break;
  }

  return "";
}

void cmaper_log_init(cmaper_logger_t *logger, FILE *stream,
                     cmaper_log_level_t level) {
  if (logger == NULL) {
    return;
  }

  logger->stream = stream != NULL ? stream : stderr;
  logger->level = cmaper_log_level_clamp(level);
  logger->use_color = cmaper_terminal_supports_color(logger->stream);
}

void cmaper_log_set_level(cmaper_logger_t *logger, cmaper_log_level_t level) {
  if (logger == NULL) {
    return;
  }

  logger->level = cmaper_log_level_clamp(level);
}

const char *cmaper_log_level_name(cmaper_log_level_t level) {
  switch (level) {
  case CMAPER_LOG_PHASE:
    return "PHASE";
  case CMAPER_LOG_INFO:
    return "INFO";
  case CMAPER_LOG_WAIT:
    return "WAIT";
  case CMAPER_LOG_OK:
    return "OK";
  case CMAPER_LOG_WARN:
    return "WARN";
  case CMAPER_LOG_FAIL:
    return "FAIL";
  case CMAPER_LOG_QUIET:
    break;
  }

  return "QUIET";
}

void cmaper_log(cmaper_logger_t *logger, cmaper_log_level_t level,
                const char *fmt, ...) {
  va_list args;
  FILE *stream;
  const char *color;

  if (logger == NULL || fmt == NULL) {
    return;
  }

  if (level == CMAPER_LOG_QUIET || logger->level == CMAPER_LOG_QUIET ||
      level < logger->level) {
    return;
  }

  stream = logger->stream != NULL ? logger->stream : stderr;
  color = logger->use_color ? cmaper_log_level_color(level) : "";

  if (logger->use_color && color[0] != '\0') {
    fprintf(stream, "%s", color);
  }

  fprintf(stream, "[%s] ", cmaper_log_level_name(level));

  if (logger->use_color && color[0] != '\0') {
    fputs("\033[0m", stream);
  }

  va_start(args, fmt);
  vfprintf(stream, fmt, args);
  va_end(args);

  fputc('\n', stream);
}
