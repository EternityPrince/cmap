#include "cmaper/platform/terminal.h"

#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <io.h>
#define CMAPER_FILENO _fileno
#define CMAPER_ISATTY _isatty
#else
#include <unistd.h>
#define CMAPER_FILENO fileno
#define CMAPER_ISATTY isatty
#endif

bool cmaper_terminal_is_tty(FILE *stream) {
  if (stream == NULL) {
    return false;
  }

  return CMAPER_ISATTY(CMAPER_FILENO(stream)) == 1;
}

bool cmaper_terminal_supports_color(FILE *stream) {
  const char *no_color = getenv("NO_COLOR");
  const char *term = getenv("TERM");

  if (!cmaper_terminal_is_tty(stream)) {
    return false;
  }

  if (no_color != NULL && no_color[0] != '\0') {
    return false;
  }

  if (term == NULL || term[0] == '\0') {
    return false;
  }

  if (strcmp(term, "dumb") == 0) {
    return false;
  }

  return true;
}
