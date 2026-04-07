#ifndef CMAPER_PLATFORM_FS_H
#define CMAPER_PLATFORM_FS_H

#include <stdbool.h>
#include <stddef.h>

#include "cmaper/core/error.h"

bool cmaper_fs_path_exists(const char *path);
bool cmaper_fs_path_is_directory(const char *path);
bool cmaper_fs_path_is_executable(const char *path);
cmaper_err_t cmaper_fs_ensure_directory(const char *path);
cmaper_err_t cmaper_fs_ensure_directory_recursive(const char *path);
cmaper_err_t cmaper_fs_parent_directory(const char *path, char *out,
                                        size_t out_cap);

#endif
