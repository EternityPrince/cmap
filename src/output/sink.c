#include "cmaper/output/sink.h"

#include <stdio.h>
#include <stdlib.h>

#include "cmaper/platform/clipboard.h"
#include "cmaper/platform/fs.h"
#include "cmaper/platform/terminal.h"

static cmaper_err_t cmaper_output_sink_prepare_parent_dir(const char *path) {
  char parent[1024];
  cmaper_err_t rc;

  if (path == NULL || path[0] == '\0') {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  rc = cmaper_fs_parent_directory(path, parent, sizeof(parent));
  if (rc != CMAPER_OK) {
    return rc;
  }

  return cmaper_fs_ensure_directory_recursive(parent);
}

static cmaper_err_t cmaper_output_sink_read_all(FILE *stream, char **out_data,
                                                size_t *out_size) {
  long size_long;
  size_t size;
  char *data;

  if (stream == NULL || out_data == NULL || out_size == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  *out_data = NULL;
  *out_size = 0;

  if (fflush(stream) != 0) {
    return CMAPER_ERR_IO;
  }
  if (fseek(stream, 0L, SEEK_END) != 0) {
    return CMAPER_ERR_IO;
  }

  size_long = ftell(stream);
  if (size_long < 0) {
    return CMAPER_ERR_IO;
  }
  size = (size_t)size_long;

  if (fseek(stream, 0L, SEEK_SET) != 0) {
    return CMAPER_ERR_IO;
  }

  data = (char *)malloc(size + 1U);
  if (data == NULL) {
    return CMAPER_ERR_OOM;
  }

  if (size > 0) {
    size_t read_size = fread(data, 1, size, stream);
    if (read_size != size) {
      free(data);
      return CMAPER_ERR_IO;
    }
  }
  data[size] = '\0';

  *out_data = data;
  *out_size = size;
  return CMAPER_OK;
}

void cmaper_output_sink_init(cmaper_output_sink_t *sink) {
  if (sink == NULL) {
    return;
  }

  sink->stream = NULL;
  sink->owns_stream = false;
  sink->capture_for_clipboard = false;
}

cmaper_err_t cmaper_output_sink_open(cmaper_output_sink_t *sink,
                                     const cmaper_output_options_t *options,
                                     FILE *default_stream,
                                     cmaper_logger_t *logger) {
  FILE *stream;
  cmaper_err_t rc;

  if (sink == NULL || options == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  cmaper_output_sink_init(sink);
  sink->stream = default_stream != NULL ? default_stream : stdout;

  switch (options->target) {
  case CMAPER_OUTPUT_TARGET_TERMINAL:
    return CMAPER_OK;
  case CMAPER_OUTPUT_TARGET_FILE:
    if (options->target_path == NULL || options->target_path[0] == '\0') {
      return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = cmaper_output_sink_prepare_parent_dir(options->target_path);
    if (rc != CMAPER_OK) {
      return rc;
    }

    stream = fopen(options->target_path, "wb");
    if (stream == NULL) {
      return CMAPER_ERR_IO;
    }

    sink->stream = stream;
    sink->owns_stream = true;
    cmaper_log(logger, CMAPER_LOG_INFO, "output: writing report to '%s'",
               options->target_path);
    return CMAPER_OK;
  case CMAPER_OUTPUT_TARGET_CLIPBOARD:
    stream = tmpfile();
    if (stream == NULL) {
      return CMAPER_ERR_IO;
    }
    sink->stream = stream;
    sink->owns_stream = true;
    sink->capture_for_clipboard = true;
    return CMAPER_OK;
  }

  return CMAPER_ERR_INVALID_ARGUMENT;
}

bool cmaper_output_sink_should_use_ansi(const cmaper_output_options_t *options,
                                        FILE *stream) {
  if (options == NULL || stream == NULL) {
    return false;
  }

  if (!options->use_color) {
    return false;
  }
  if (options->format != CMAPER_OUTPUT_FORMAT_TERMINAL) {
    return false;
  }
  if (options->target != CMAPER_OUTPUT_TARGET_TERMINAL) {
    return false;
  }

  return cmaper_terminal_supports_color(stream);
}

cmaper_err_t cmaper_output_sink_finalize(cmaper_output_sink_t *sink,
                                         const cmaper_output_options_t *options,
                                         FILE *default_stream,
                                         cmaper_logger_t *logger) {
  cmaper_err_t rc = CMAPER_OK;

  if (sink == NULL || options == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  if (sink->capture_for_clipboard) {
    char *data = NULL;
    size_t data_size = 0;
    cmaper_err_t read_rc =
        cmaper_output_sink_read_all(sink->stream, &data, &data_size);
    if (read_rc != CMAPER_OK) {
      rc = read_rc;
    } else {
      cmaper_err_t clip_rc = cmaper_platform_clipboard_copy(data, data_size);
      if (clip_rc == CMAPER_OK) {
        cmaper_log(logger, CMAPER_LOG_OK, "output: report copied to clipboard");
      } else {
        FILE *fallback = default_stream != NULL ? default_stream : stdout;
        cmaper_log(logger, CMAPER_LOG_WARN,
                   "output: clipboard copy failed, printing report instead");
        if (data_size > 0) {
          (void)fwrite(data, 1, data_size, fallback);
        }
      }
    }

    if (data != NULL) {
      free(data);
    }
  }

  if (sink->owns_stream && sink->stream != NULL) {
    if (fclose(sink->stream) != 0 && rc == CMAPER_OK) {
      rc = CMAPER_ERR_IO;
    }
  } else if (sink->stream != NULL) {
    if (fflush(sink->stream) != 0 && rc == CMAPER_OK) {
      rc = CMAPER_ERR_IO;
    }
  }

  cmaper_output_sink_init(sink);
  return rc;
}
