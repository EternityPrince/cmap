#ifndef CMAPER_CLI_PARSER_H
#define CMAPER_CLI_PARSER_H

#include "cmaper/cli/config.h"
#include "cmaper/cli/diagnostic.h"
#include "cmaper/cli/raw.h"
#include "cmaper/core/error.h"

cmaper_err_t cmaper_cli_normalize_config(
    cmaper_cli_config_t *config,
    const cmaper_cli_raw_args_t *raw,
    cmaper_cli_diagnostic_t *diag
);

#endif
