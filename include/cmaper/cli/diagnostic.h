#ifndef CMAPER_CLI_DIAGNOSTIC_H
#define CMAPER_CLI_DIAGNOSTIC_H

#include <stdarg.h>

#define CMAPER_CLI_DIAG_MESSAGE_CAP 256

typedef struct {
    const char *argument;
    char message[CMAPER_CLI_DIAG_MESSAGE_CAP];
} cmaper_cli_diagnostic_t;

void cmaper_cli_diag_clear(cmaper_cli_diagnostic_t *diag);
void cmaper_cli_diag_set(
    cmaper_cli_diagnostic_t *diag,
    const char *argument,
    const char *message
);
void cmaper_cli_diag_setf(
    cmaper_cli_diagnostic_t *diag,
    const char *argument,
    const char *fmt,
    ...
);
void cmaper_cli_diag_vsetf(
    cmaper_cli_diagnostic_t *diag,
    const char *argument,
    const char *fmt,
    va_list args
);

#endif
