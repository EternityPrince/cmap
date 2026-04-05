#include "cmaper/platform/fs.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif

#if defined(_WIN32)
#include <direct.h>
#define CMAPER_MKDIR(path) _mkdir(path)
#include <io.h>
#define CMAPER_ACCESS _access
#define CMAPER_X_OK 4
#else
#define CMAPER_MKDIR(path) mkdir(path, 0755)
#define CMAPER_ACCESS access
#define CMAPER_X_OK X_OK
#endif

bool cmaper_fs_path_exists(const char *path) {
    struct stat st;

    if (path == NULL || path[0] == '\0') {
        return false;
    }

    return stat(path, &st) == 0;
}

bool cmaper_fs_path_is_directory(const char *path) {
    struct stat st;

    if (path == NULL || path[0] == '\0') {
        return false;
    }

    if (stat(path, &st) != 0) {
        return false;
    }

    return S_ISDIR(st.st_mode);
}

bool cmaper_fs_path_is_executable(const char *path) {
    if (path == NULL || path[0] == '\0') {
        return false;
    }

    return CMAPER_ACCESS(path, CMAPER_X_OK) == 0;
}

cmaper_err_t cmaper_fs_ensure_directory(const char *path) {
    if (path == NULL || path[0] == '\0') {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    if (cmaper_fs_path_exists(path)) {
        return CMAPER_OK;
    }

    if (CMAPER_MKDIR(path) == 0 || errno == EEXIST) {
        return CMAPER_OK;
    }

    return CMAPER_ERR_IO;
}

cmaper_err_t cmaper_fs_ensure_directory_recursive(const char *path) {
    char buffer[1024];
    size_t i;
    size_t length;

    if (path == NULL || path[0] == '\0') {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    length = strlen(path);
    if (length >= sizeof(buffer)) {
        return CMAPER_ERR_IO;
    }

    memcpy(buffer, path, length + 1);

    for (i = 1; i < length; ++i) {
        if (buffer[i] == '/') {
            buffer[i] = '\0';
            if (buffer[0] != '\0' && !cmaper_fs_path_is_directory(buffer)) {
                if (CMAPER_MKDIR(buffer) != 0 && errno != EEXIST) {
                    return CMAPER_ERR_IO;
                }
            }
            buffer[i] = '/';
        }
    }

    if (!cmaper_fs_path_is_directory(buffer)) {
        if (CMAPER_MKDIR(buffer) != 0 && errno != EEXIST) {
            return CMAPER_ERR_IO;
        }
    }

    return CMAPER_OK;
}

cmaper_err_t cmaper_fs_parent_directory(const char *path, char *out, size_t out_cap) {
    const char *slash;
    size_t length;

    if (path == NULL || out == NULL || out_cap == 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    slash = strrchr(path, '/');
    if (slash == NULL) {
        if (snprintf(out, out_cap, ".") >= (int) out_cap) {
            return CMAPER_ERR_IO;
        }
        return CMAPER_OK;
    }

    length = (size_t) (slash - path);
    if (length == 0) {
        if (snprintf(out, out_cap, "/") >= (int) out_cap) {
            return CMAPER_ERR_IO;
        }
        return CMAPER_OK;
    }

    if (length >= out_cap) {
        return CMAPER_ERR_IO;
    }

    memcpy(out, path, length);
    out[length] = '\0';
    return CMAPER_OK;
}
