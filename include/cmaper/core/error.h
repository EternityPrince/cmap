#ifndef CMAPER_CORE_ERROR_H
#define CMAPER_CORE_ERROR_H

typedef enum {
    CMAPER_OK = 0,
    CMAPER_ERR_CLI_USAGE,
    CMAPER_ERR_INVALID_ARGUMENT,
    CMAPER_ERR_IO,
    CMAPER_ERR_OOM,
    CMAPER_ERR_PARSE,
    CMAPER_ERR_UNIMPLEMENTED,
    CMAPER_ERR_INTERNAL
} cmaper_err_t;

const char *cmaper_err_str(cmaper_err_t error);
int cmaper_err_to_exit_code(cmaper_err_t error);

#endif
