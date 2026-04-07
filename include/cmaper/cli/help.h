#ifndef CMAPER_CLI_HELP_H
#define CMAPER_CLI_HELP_H

#include <stdio.h>

void cmaper_cli_print_help(FILE *stream, const char *program_name,
                           const char *topic);
void cmaper_cli_print_version(FILE *stream, const char *program_name);

#endif
