#include "cmaper/platform/clipboard.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static cmaper_err_t cmaper_platform_clipboard_run_command(const char *command,
                                                          const char *data,
                                                          size_t data_size) {
  FILE *pipe;
  size_t written = 0;
  int close_rc;

  if (command == NULL || data == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  pipe = popen(command, "w");
  if (pipe == NULL) {
    return CMAPER_ERR_IO;
  }

  while (written < data_size) {
    size_t chunk = fwrite(data + written, 1, data_size - written, pipe);
    if (chunk == 0) {
      break;
    }
    written += chunk;
  }

  close_rc = pclose(pipe);
  if (written != data_size || close_rc != 0) {
    return CMAPER_ERR_IO;
  }

  return CMAPER_OK;
}

cmaper_err_t cmaper_platform_clipboard_copy(const char *data,
                                            size_t data_size) {
  static const char *COMMANDS[] = {
#if defined(__APPLE__)
      "pbcopy",
#elif defined(_WIN32)
      "clip",
#else
      "wl-copy",
      "xclip -selection clipboard",
      "xsel --clipboard --input",
#endif
  };
  size_t i;

  if (data == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  for (i = 0; i < sizeof(COMMANDS) / sizeof(COMMANDS[0]); ++i) {
    cmaper_err_t rc =
        cmaper_platform_clipboard_run_command(COMMANDS[i], data, data_size);
    if (rc == CMAPER_OK) {
      return CMAPER_OK;
    }
  }

  return CMAPER_ERR_UNIMPLEMENTED;
}
