#include "cmaper/core/error.h"

const char *cmaper_err_str(cmaper_err_t error) {
    switch (error) {
    case CMAPER_OK:
        return "ok";
    case CMAPER_ERR_CLI_USAGE:
        return "cli usage error";
    case CMAPER_ERR_INVALID_ARGUMENT:
        return "invalid argument";
    case CMAPER_ERR_IO:
        return "i/o error";
    case CMAPER_ERR_OOM:
        return "out of memory";
    case CMAPER_ERR_PARSE:
        return "parse error";
    case CMAPER_ERR_UNIMPLEMENTED:
        return "unimplemented";
    case CMAPER_ERR_INTERNAL:
        return "internal error";
    }

    return "unknown error";
}

int cmaper_err_to_exit_code(cmaper_err_t error) {
    switch (error) {
    case CMAPER_OK:
        return 0;
    case CMAPER_ERR_CLI_USAGE:
        return 2;
    default:
        return 1;
    }
}
