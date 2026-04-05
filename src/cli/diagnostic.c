#include "cmaper/cli/diagnostic.h"

#include <stdio.h>
#include <string.h>

void cmaper_cli_diag_clear(cmaper_cli_diagnostic_t *diag) {
    if (diag == NULL) {
        return;
    }

    diag->argument = NULL;
    diag->message[0] = '\0';
}

void cmaper_cli_diag_set(
    cmaper_cli_diagnostic_t *diag,
    const char *argument,
    const char *message
) {
    cmaper_cli_diag_clear(diag);

    if (diag == NULL) {
        return;
    }

    diag->argument = argument;

    if (message == NULL) {
        return;
    }

    snprintf(diag->message, sizeof(diag->message), "%s", message);
}

void cmaper_cli_diag_setf(
    cmaper_cli_diagnostic_t *diag,
    const char *argument,
    const char *fmt,
    ...
) {
    va_list args;

    va_start(args, fmt);
    cmaper_cli_diag_vsetf(diag, argument, fmt, args);
    va_end(args);
}

void cmaper_cli_diag_vsetf(
    cmaper_cli_diagnostic_t *diag,
    const char *argument,
    const char *fmt,
    va_list args
) {
    cmaper_cli_diag_clear(diag);

    if (diag == NULL) {
        return;
    }

    diag->argument = argument;

    if (fmt == NULL) {
        return;
    }

    vsnprintf(diag->message, sizeof(diag->message), fmt, args);
}
