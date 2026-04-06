#ifndef CMAPER_RUNTIME_PATHS_H
#define CMAPER_RUNTIME_PATHS_H

#include <stdbool.h>
#include <stddef.h>

#include "cmaper/core/error.h"

#define CMAPER_RUNTIME_PATH_CAP 1024
#define CMAPER_RUNTIME_PATH_DIAG_CAP 256

typedef struct {
    const char *field;
    char message[CMAPER_RUNTIME_PATH_DIAG_CAP];
} cmaper_runtime_paths_diag_t;

typedef struct {
    char db_path[CMAPER_RUNTIME_PATH_CAP];
    char db_dir[CMAPER_RUNTIME_PATH_CAP];
    char xml_output_dir[CMAPER_RUNTIME_PATH_CAP];
    char nmap_bin[CMAPER_RUNTIME_PATH_CAP];
    char nmap_scripts_dir[CMAPER_RUNTIME_PATH_CAP];
    bool nmap_bin_from_env;
    bool nmap_scripts_dir_from_env;
    bool has_nmap_scripts_dir;
} cmaper_runtime_paths_t;

void cmaper_runtime_paths_diag_clear(cmaper_runtime_paths_diag_t *diag);
void cmaper_runtime_paths_init(cmaper_runtime_paths_t *paths);

const char *cmaper_runtime_env_nmap_bin(void);
const char *cmaper_runtime_env_nmap_scripts_dir(void);

cmaper_err_t cmaper_runtime_paths_resolve(
    cmaper_runtime_paths_t *paths,
    cmaper_runtime_paths_diag_t *diag
);

#endif
