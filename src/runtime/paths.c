#include "cmaper/runtime/paths.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cmaper/platform/fs.h"

static void cmaper_runtime_paths_diag_setf(cmaper_runtime_paths_diag_t *diag,
                                           const char *field, const char *fmt,
                                           ...) {
  va_list args;

  cmaper_runtime_paths_diag_clear(diag);
  if (diag == NULL) {
    return;
  }

  diag->field = field;
  if (fmt == NULL) {
    return;
  }

  va_start(args, fmt);
  vsnprintf(diag->message, sizeof(diag->message), fmt, args);
  va_end(args);
}

static const char *cmaper_runtime_getenv_nonempty(const char *name) {
  const char *value;

  if (name == NULL || name[0] == '\0') {
    return NULL;
  }

  value = getenv(name);
  if (value == NULL || value[0] == '\0') {
    return NULL;
  }

  return value;
}

static const char *cmaper_runtime_getenv_compat(const char *nm_name,
                                                const char *cm_name) {
  const char *value = cmaper_runtime_getenv_nonempty(cm_name);

  if (value != NULL) {
    return value;
  }

  return cmaper_runtime_getenv_nonempty(nm_name);
}

static cmaper_err_t
cmaper_runtime_copy_string(char *out, size_t out_cap, const char *value,
                           cmaper_runtime_paths_diag_t *diag,
                           const char *field) {
  int written;

  if (out == NULL || out_cap == 0 || value == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  written = snprintf(out, out_cap, "%s", value);
  if (written < 0 || (size_t)written >= out_cap) {
    cmaper_runtime_paths_diag_setf(
        diag, field, "resolved path for '%s' exceeds internal buffer limit",
        field);
    return CMAPER_ERR_IO;
  }

  return CMAPER_OK;
}

static cmaper_err_t cmaper_runtime_join_path(char *out, size_t out_cap,
                                             const char *left,
                                             const char *right,
                                             cmaper_runtime_paths_diag_t *diag,
                                             const char *field) {
  int written;

  if (left == NULL || right == NULL || left[0] == '\0' || right[0] == '\0') {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  if (left[strlen(left) - 1] == '/') {
    written = snprintf(out, out_cap, "%s%s", left, right);
  } else {
    written = snprintf(out, out_cap, "%s/%s", left, right);
  }

  if (written < 0 || (size_t)written >= out_cap) {
    cmaper_runtime_paths_diag_setf(
        diag, field, "resolved path for '%s' exceeds internal buffer limit",
        field);
    return CMAPER_ERR_IO;
  }

  return CMAPER_OK;
}

static bool cmaper_runtime_is_nmap_binary_candidate(const char *path) {
  size_t len;
  size_t suffix_len;

  if (path == NULL || path[0] == '\0') {
    return false;
  }

  len = strlen(path);
  suffix_len = strlen("/bin/nmap");

  if (len < suffix_len) {
    return false;
  }

  return strcmp(path + len - suffix_len, "/bin/nmap") == 0;
}

static cmaper_err_t cmaper_runtime_find_in_path(const char *binary_name,
                                                char *out_path,
                                                size_t out_cap) {
  const char *path_env = getenv("PATH");
  const char *cursor;

  if (binary_name == NULL || binary_name[0] == '\0' || out_path == NULL ||
      out_cap == 0) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  out_path[0] = '\0';
  if (path_env == NULL || path_env[0] == '\0') {
    return CMAPER_ERR_IO;
  }

  cursor = path_env;
  while (cursor[0] != '\0') {
    const char *sep = strchr(cursor, ':');
    char dir[CMAPER_RUNTIME_PATH_CAP];
    char candidate[CMAPER_RUNTIME_PATH_CAP];
    size_t dir_len;
    int written;

    if (sep != NULL) {
      dir_len = (size_t)(sep - cursor);
    } else {
      dir_len = strlen(cursor);
    }

    if (dir_len > 0 && dir_len < sizeof(dir)) {
      memcpy(dir, cursor, dir_len);
      dir[dir_len] = '\0';

      written =
          snprintf(candidate, sizeof(candidate), "%s/%s", dir, binary_name);
      if (written > 0 && (size_t)written < sizeof(candidate) &&
          cmaper_fs_path_is_executable(candidate)) {
        return cmaper_runtime_copy_string(out_path, out_cap, candidate, NULL,
                                          NULL);
      }
    }

    if (sep == NULL) {
      break;
    }
    cursor = sep + 1;
  }

  return CMAPER_ERR_IO;
}

static void
cmaper_runtime_try_default_scripts_dir(cmaper_runtime_paths_t *paths) {
  static const char *candidates[] = {"/usr/share/nmap/scripts",
                                     "/usr/local/share/nmap/scripts",
                                     "/opt/homebrew/share/nmap/scripts"};
  size_t i;

  for (i = 0; i < (sizeof(candidates) / sizeof(candidates[0])); ++i) {
    if (cmaper_fs_path_is_directory(candidates[i])) {
      snprintf(paths->nmap_scripts_dir, sizeof(paths->nmap_scripts_dir), "%s",
               candidates[i]);
      paths->has_nmap_scripts_dir = true;
      return;
    }
  }

  paths->nmap_scripts_dir[0] = '\0';
  paths->has_nmap_scripts_dir = false;
}

void cmaper_runtime_paths_diag_clear(cmaper_runtime_paths_diag_t *diag) {
  if (diag == NULL) {
    return;
  }

  diag->field = NULL;
  diag->message[0] = '\0';
}

void cmaper_runtime_paths_init(cmaper_runtime_paths_t *paths) {
  if (paths == NULL) {
    return;
  }

  paths->db_path[0] = '\0';
  paths->db_dir[0] = '\0';
  paths->xml_output_dir[0] = '\0';
  paths->nmap_bin[0] = '\0';
  paths->nmap_scripts_dir[0] = '\0';
  paths->nmap_bin_from_env = false;
  paths->nmap_scripts_dir_from_env = false;
  paths->has_nmap_scripts_dir = false;
}

const char *cmaper_runtime_env_nmap_bin(void) {
  return cmaper_runtime_getenv_compat("NMAPER_NMAP_BIN", "CMAPER_NMAP_BIN");
}

const char *cmaper_runtime_env_nmap_scripts_dir(void) {
  return cmaper_runtime_getenv_compat("NMAPER_NMAP_SCRIPTS_DIR",
                                      "CMAPER_NMAP_SCRIPTS_DIR");
}

cmaper_err_t cmaper_runtime_paths_resolve(cmaper_runtime_paths_t *paths,
                                          cmaper_runtime_paths_diag_t *diag) {
  char cwd[CMAPER_RUNTIME_PATH_CAP];
  char data_root[CMAPER_RUNTIME_PATH_CAP];
  char inferred_scripts[CMAPER_RUNTIME_PATH_CAP];
  const char *db_env;
  const char *xml_env;
  const char *nmap_env;
  const char *scripts_env;
  const char *data_root_env;
  const char *home_dir;
  cmaper_err_t rc;

  if (paths == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  cmaper_runtime_paths_diag_clear(diag);
  cmaper_runtime_paths_init(paths);

  db_env = cmaper_runtime_getenv_compat("NMAPER_DB_PATH", "CMAPER_DB_PATH");
  xml_env = cmaper_runtime_getenv_compat("NMAPER_XML_OUTPUT_DIR",
                                         "CMAPER_XML_OUTPUT_DIR");
  nmap_env = cmaper_runtime_env_nmap_bin();
  scripts_env = cmaper_runtime_env_nmap_scripts_dir();
  data_root_env =
      cmaper_runtime_getenv_compat("NMAPER_DATA_DIR", "CMAPER_DATA_DIR");
  home_dir = cmaper_runtime_getenv_nonempty("HOME");

  if (data_root_env != NULL) {
    if (snprintf(data_root, sizeof(data_root), "%s", data_root_env) >=
        (int)sizeof(data_root)) {
      cmaper_runtime_paths_diag_setf(diag, "data-root",
                                     "resolved data root path is too long");
      return CMAPER_ERR_IO;
    }
  } else if (home_dir != NULL) {
    if (snprintf(data_root, sizeof(data_root), "%s/.local/share/cmaper",
                 home_dir) >= (int)sizeof(data_root)) {
      cmaper_runtime_paths_diag_setf(diag, "data-root",
                                     "resolved data root path is too long");
      return CMAPER_ERR_IO;
    }
  } else if (getcwd(cwd, sizeof(cwd)) != NULL) {
    if (snprintf(data_root, sizeof(data_root), "%s/.cmaper", cwd) >=
        (int)sizeof(data_root)) {
      cmaper_runtime_paths_diag_setf(diag, "data-root",
                                     "resolved data root path is too long");
      return CMAPER_ERR_IO;
    }
  } else {
    if (snprintf(data_root, sizeof(data_root), ".cmaper") >=
        (int)sizeof(data_root)) {
      cmaper_runtime_paths_diag_setf(diag, "data-root",
                                     "resolved data root path is too long");
      return CMAPER_ERR_IO;
    }
  }

  if (data_root[0] == '\0') {
    cmaper_runtime_paths_diag_setf(diag, "data-root",
                                   "resolved data root path is too long");
    return CMAPER_ERR_IO;
  }

  if (db_env != NULL) {
    rc = cmaper_runtime_copy_string(paths->db_path, sizeof(paths->db_path),
                                    db_env, diag, "db-path");
  } else {
    rc = cmaper_runtime_join_path(paths->db_path, sizeof(paths->db_path),
                                  data_root, "cmaper.db", diag, "db-path");
  }
  if (rc != CMAPER_OK) {
    return rc;
  }

  if (xml_env != NULL) {
    rc = cmaper_runtime_copy_string(paths->xml_output_dir,
                                    sizeof(paths->xml_output_dir), xml_env,
                                    diag, "xml-output-dir");
  } else {
    rc = cmaper_runtime_join_path(paths->xml_output_dir,
                                  sizeof(paths->xml_output_dir), data_root,
                                  "xml", diag, "xml-output-dir");
  }
  if (rc != CMAPER_OK) {
    return rc;
  }

  rc = cmaper_fs_parent_directory(paths->db_path, paths->db_dir,
                                  sizeof(paths->db_dir));
  if (rc != CMAPER_OK) {
    cmaper_runtime_paths_diag_setf(
        diag, "db-path", "cannot resolve parent directory for db path");
    return rc;
  }

  if (nmap_env != NULL) {
    paths->nmap_bin_from_env = true;
    rc = cmaper_runtime_copy_string(paths->nmap_bin, sizeof(paths->nmap_bin),
                                    nmap_env, diag, "nmap-bin");
  } else {
    rc = cmaper_runtime_find_in_path("nmap", paths->nmap_bin,
                                     sizeof(paths->nmap_bin));
  }
  if (rc != CMAPER_OK && nmap_env != NULL) {
    return rc;
  }
  if (rc != CMAPER_OK) {
    paths->nmap_bin[0] = '\0';
  }

  if (scripts_env != NULL) {
    paths->nmap_scripts_dir_from_env = true;
    rc = cmaper_runtime_copy_string(paths->nmap_scripts_dir,
                                    sizeof(paths->nmap_scripts_dir),
                                    scripts_env, diag, "nmap-scripts-dir");
    if (rc != CMAPER_OK) {
      return rc;
    }
    paths->has_nmap_scripts_dir = true;
  } else if (cmaper_runtime_is_nmap_binary_candidate(paths->nmap_bin)) {
    size_t nmap_bin_len = strlen(paths->nmap_bin);
    size_t root_len = nmap_bin_len - strlen("/bin/nmap");
    int written;

    if (root_len >= sizeof(inferred_scripts)) {
      cmaper_runtime_paths_diag_setf(diag, "nmap-scripts-dir",
                                     "derived scripts path is too long");
      return CMAPER_ERR_IO;
    }

    memcpy(inferred_scripts, paths->nmap_bin, root_len);
    inferred_scripts[root_len] = '\0';

    written = snprintf(paths->nmap_scripts_dir, sizeof(paths->nmap_scripts_dir),
                       "%s/share/nmap/scripts", inferred_scripts);
    if (written < 0 || (size_t)written >= sizeof(paths->nmap_scripts_dir)) {
      cmaper_runtime_paths_diag_setf(diag, "nmap-scripts-dir",
                                     "derived scripts path is too long");
      return CMAPER_ERR_IO;
    }

    paths->has_nmap_scripts_dir =
        cmaper_fs_path_is_directory(paths->nmap_scripts_dir);
    if (!paths->has_nmap_scripts_dir) {
      cmaper_runtime_try_default_scripts_dir(paths);
    }
  } else {
    cmaper_runtime_try_default_scripts_dir(paths);
  }

  return CMAPER_OK;
}
