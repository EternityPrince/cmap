#ifndef CMAPER_CLI_VALIDATE_H
#define CMAPER_CLI_VALIDATE_H

#include "cmaper/cli/config.h"
#include "cmaper/cli/diagnostic.h"
#include "cmaper/core/error.h"

cmaper_err_t cmaper_cli_validate_config(
    const cmaper_cli_config_t *config,
    cmaper_cli_diagnostic_t *diag
);

#endif
