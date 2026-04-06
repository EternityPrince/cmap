#ifndef CMAPER_PLATFORM_TERMINAL_H
#define CMAPER_PLATFORM_TERMINAL_H

#include <stdbool.h>
#include <stdio.h>

bool cmaper_terminal_is_tty(FILE *stream);
bool cmaper_terminal_supports_color(FILE *stream);

#endif
