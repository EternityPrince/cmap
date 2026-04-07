#include "cmaper/cli/raw.h"

#include <string.h>

static const char *cmaper_cli_inline_value(const char *arg,
                                           const char *option) {
  size_t option_len;

  if (arg == NULL || option == NULL) {
    return NULL;
  }

  option_len = strlen(option);

  if (strncmp(arg, option, option_len) != 0) {
    return NULL;
  }

  if (arg[option_len] != '=') {
    return NULL;
  }

  return arg + option_len + 1;
}

static cmaper_err_t
cmaper_cli_take_option_value(int argc, char **argv, int *index,
                             const char *option, const char *inline_value,
                             const char **out, cmaper_cli_diagnostic_t *diag) {
  if (inline_value != NULL) {
    *out = inline_value;
    return CMAPER_OK;
  }

  if ((*index + 1) >= argc) {
    cmaper_cli_diag_setf(diag, option, "option '%s' requires a value", option);
    return CMAPER_ERR_CLI_USAGE;
  }

  *out = argv[*index + 1];
  *index += 1;
  return CMAPER_OK;
}

static cmaper_err_t cmaper_cli_assign_once(const char **slot, const char *value,
                                           const char *option,
                                           cmaper_cli_diagnostic_t *diag) {
  if (*slot != NULL) {
    cmaper_cli_diag_setf(diag, option, "option '%s' can be specified only once",
                         option);
    return CMAPER_ERR_CLI_USAGE;
  }

  *slot = value;
  return CMAPER_OK;
}

void cmaper_cli_raw_args_init(cmaper_cli_raw_args_t *raw) {
  size_t i;

  if (raw == NULL) {
    return;
  }

  raw->program_name = "cmaper";
  raw->wants_help = false;
  raw->wants_version = false;
  raw->wants_check = false;
  raw->wants_dev = false;
  raw->xml_only = false;
  raw->verbosity_delta = 0;
  raw->use_json_shortcut = false;
  raw->wants_color = false;
  raw->wants_no_color = false;
  raw->confirm_delete_all = false;
  raw->mode_token = NULL;

  raw->scan_profile = NULL;
  raw->target = NULL;
  raw->scan_ports = NULL;
  raw->enable_all_ports = false;
  raw->disable_all_ports = false;
  raw->enable_no_ping = false;
  raw->disable_no_ping = false;
  raw->scan_timing = NULL;
  raw->scan_detail_workers = NULL;
  raw->enable_service_detection = false;
  raw->disable_service_detection = false;
  raw->enable_os_detection = false;
  raw->disable_os_detection = false;
  raw->enable_sudo = false;
  raw->disable_sudo = false;
  raw->spoof_mac = NULL;
  raw->disable_spoof_mac = false;
  raw->enable_traceroute = false;
  raw->disable_traceroute = false;
  raw->enable_udp_enrichment = false;
  raw->disable_udp_enrichment = false;

  raw->session_id = NULL;
  raw->from_session_id = NULL;
  raw->to_session_id = NULL;
  raw->device_id = NULL;
  raw->format = NULL;
  raw->output = NULL;
  raw->view = NULL;
  raw->limit = NULL;
  raw->window = NULL;
  raw->changes_only = false;
  raw->positional_count = 0;

  for (i = 0; i < CMAPER_CLI_MAX_POSITIONALS; ++i) {
    raw->positionals[i] = NULL;
  }
}

cmaper_err_t cmaper_cli_parse_raw_argv(cmaper_cli_raw_args_t *raw, int argc,
                                       char **argv,
                                       cmaper_cli_diagnostic_t *diag) {
  bool parse_options = true;
  int i;

  if (raw == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  cmaper_cli_diag_clear(diag);
  cmaper_cli_raw_args_init(raw);

  if (argv != NULL && argc > 0 && argv[0] != NULL) {
    raw->program_name = argv[0];
  }

  for (i = 1; i < argc; ++i) {
    const char *arg = argv[i];
    const char *inline_value = NULL;
    const char *value = NULL;
    cmaper_err_t rc = CMAPER_OK;

    if (parse_options && strcmp(arg, "--") == 0) {
      parse_options = false;
      continue;
    }

    if (parse_options && arg[0] == '-' && arg[1] != '\0') {
      if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
        raw->wants_help = true;
        continue;
      }

      if (strcmp(arg, "-V") == 0 || strcmp(arg, "--version") == 0) {
        raw->wants_version = true;
        continue;
      }

      if (strcmp(arg, "--check") == 0) {
        raw->wants_check = true;
        continue;
      }

      if (strcmp(arg, "--dev") == 0) {
        raw->wants_dev = true;
        continue;
      }

      if (strcmp(arg, "--xml-only") == 0) {
        raw->xml_only = true;
        continue;
      }

      if (strcmp(arg, "-v") == 0 || strcmp(arg, "--verbose") == 0) {
        raw->verbosity_delta += 1;
        continue;
      }

      if (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0) {
        raw->verbosity_delta -= 1;
        continue;
      }

      if (strcmp(arg, "--json") == 0) {
        raw->use_json_shortcut = true;
        continue;
      }

      if (strcmp(arg, "--color") == 0) {
        raw->wants_color = true;
        continue;
      }

      if (strcmp(arg, "--no-color") == 0) {
        raw->wants_no_color = true;
        continue;
      }

      if (strcmp(arg, "--yes") == 0) {
        raw->confirm_delete_all = true;
        continue;
      }

      inline_value = cmaper_cli_inline_value(arg, "--target");
      if (strcmp(arg, "--target") == 0 || inline_value != NULL) {
        rc = cmaper_cli_take_option_value(argc, argv, &i, "--target",
                                          inline_value, &value, diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        rc = cmaper_cli_assign_once(&raw->target, value, "--target", diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        continue;
      }

      inline_value = cmaper_cli_inline_value(arg, "--profile");
      if (strcmp(arg, "--profile") == 0 || inline_value != NULL) {
        rc = cmaper_cli_take_option_value(argc, argv, &i, "--profile",
                                          inline_value, &value, diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        rc = cmaper_cli_assign_once(&raw->scan_profile, value, "--profile",
                                    diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        continue;
      }

      inline_value = cmaper_cli_inline_value(arg, "--ports");
      if (strcmp(arg, "--ports") == 0 || inline_value != NULL) {
        rc = cmaper_cli_take_option_value(argc, argv, &i, "--ports",
                                          inline_value, &value, diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        rc = cmaper_cli_assign_once(&raw->scan_ports, value, "--ports", diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        continue;
      }

      if (strcmp(arg, "--no-ping") == 0) {
        raw->enable_no_ping = true;
        continue;
      }

      if (strcmp(arg, "--ping") == 0) {
        raw->disable_no_ping = true;
        continue;
      }

      if (strcmp(arg, "--all-ports") == 0) {
        raw->enable_all_ports = true;
        continue;
      }

      if (strcmp(arg, "--no-all-ports") == 0) {
        raw->disable_all_ports = true;
        continue;
      }

      inline_value = cmaper_cli_inline_value(arg, "--exact-ports");
      if (strcmp(arg, "--exact-ports") == 0 || inline_value != NULL) {
        rc = cmaper_cli_take_option_value(argc, argv, &i, "--exact-ports",
                                          inline_value, &value, diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        rc = cmaper_cli_assign_once(&raw->scan_ports, value, "--exact-ports",
                                    diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        continue;
      }

      inline_value = cmaper_cli_inline_value(arg, "--timing");
      if (strcmp(arg, "--timing") == 0 || inline_value != NULL) {
        rc = cmaper_cli_take_option_value(argc, argv, &i, "--timing",
                                          inline_value, &value, diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        rc = cmaper_cli_assign_once(&raw->scan_timing, value, "--timing", diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        continue;
      }

      inline_value = cmaper_cli_inline_value(arg, "--detail-workers");
      if (strcmp(arg, "--detail-workers") == 0 || inline_value != NULL) {
        rc = cmaper_cli_take_option_value(argc, argv, &i, "--detail-workers",
                                          inline_value, &value, diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        rc = cmaper_cli_assign_once(&raw->scan_detail_workers, value,
                                    "--detail-workers", diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        continue;
      }

      inline_value = cmaper_cli_inline_value(arg, "--spoof-mac");
      if (strcmp(arg, "--spoof-mac") == 0 || inline_value != NULL) {
        rc = cmaper_cli_take_option_value(argc, argv, &i, "--spoof-mac",
                                          inline_value, &value, diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        rc =
            cmaper_cli_assign_once(&raw->spoof_mac, value, "--spoof-mac", diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        continue;
      }

      if (strcmp(arg, "--service-detection") == 0) {
        raw->enable_service_detection = true;
        continue;
      }

      if (strcmp(arg, "--no-service-detection") == 0) {
        raw->disable_service_detection = true;
        continue;
      }

      if (strcmp(arg, "--os-detection") == 0) {
        raw->enable_os_detection = true;
        continue;
      }

      if (strcmp(arg, "--no-os-detection") == 0) {
        raw->disable_os_detection = true;
        continue;
      }

      if (strcmp(arg, "--sudo") == 0) {
        raw->enable_sudo = true;
        continue;
      }

      if (strcmp(arg, "--no-sudo") == 0) {
        raw->disable_sudo = true;
        continue;
      }

      if (strcmp(arg, "--no-spoof-mac") == 0) {
        raw->disable_spoof_mac = true;
        continue;
      }

      if (strcmp(arg, "--traceroute") == 0) {
        raw->enable_traceroute = true;
        continue;
      }

      if (strcmp(arg, "--no-traceroute") == 0) {
        raw->disable_traceroute = true;
        continue;
      }

      if (strcmp(arg, "--udp-enrichment") == 0) {
        raw->enable_udp_enrichment = true;
        continue;
      }

      if (strcmp(arg, "--no-udp-enrichment") == 0) {
        raw->disable_udp_enrichment = true;
        continue;
      }

      inline_value = cmaper_cli_inline_value(arg, "--session");
      if (strcmp(arg, "--session") == 0 || inline_value != NULL) {
        rc = cmaper_cli_take_option_value(argc, argv, &i, "--session",
                                          inline_value, &value, diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        rc = cmaper_cli_assign_once(&raw->session_id, value, "--session", diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        continue;
      }

      inline_value = cmaper_cli_inline_value(arg, "--session-id");
      if (strcmp(arg, "--session-id") == 0 || inline_value != NULL) {
        rc = cmaper_cli_take_option_value(argc, argv, &i, "--session-id",
                                          inline_value, &value, diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        rc = cmaper_cli_assign_once(&raw->session_id, value, "--session-id",
                                    diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        continue;
      }

      inline_value = cmaper_cli_inline_value(arg, "--from");
      if (strcmp(arg, "--from") == 0 || inline_value != NULL) {
        rc = cmaper_cli_take_option_value(argc, argv, &i, "--from",
                                          inline_value, &value, diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        rc = cmaper_cli_assign_once(&raw->from_session_id, value, "--from",
                                    diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        continue;
      }

      inline_value = cmaper_cli_inline_value(arg, "--to");
      if (strcmp(arg, "--to") == 0 || inline_value != NULL) {
        rc = cmaper_cli_take_option_value(argc, argv, &i, "--to", inline_value,
                                          &value, diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        rc = cmaper_cli_assign_once(&raw->to_session_id, value, "--to", diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        continue;
      }

      inline_value = cmaper_cli_inline_value(arg, "--device");
      if (strcmp(arg, "--device") == 0 || inline_value != NULL) {
        rc = cmaper_cli_take_option_value(argc, argv, &i, "--device",
                                          inline_value, &value, diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        rc = cmaper_cli_assign_once(&raw->device_id, value, "--device", diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        continue;
      }

      inline_value = cmaper_cli_inline_value(arg, "--device-id");
      if (strcmp(arg, "--device-id") == 0 || inline_value != NULL) {
        rc = cmaper_cli_take_option_value(argc, argv, &i, "--device-id",
                                          inline_value, &value, diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        rc =
            cmaper_cli_assign_once(&raw->device_id, value, "--device-id", diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        continue;
      }

      inline_value = cmaper_cli_inline_value(arg, "--format");
      if (strcmp(arg, "--format") == 0 || inline_value != NULL) {
        rc = cmaper_cli_take_option_value(argc, argv, &i, "--format",
                                          inline_value, &value, diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        rc = cmaper_cli_assign_once(&raw->format, value, "--format", diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        continue;
      }

      inline_value = cmaper_cli_inline_value(arg, "--output");
      if (strcmp(arg, "--output") == 0 || inline_value != NULL) {
        rc = cmaper_cli_take_option_value(argc, argv, &i, "--output",
                                          inline_value, &value, diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        rc = cmaper_cli_assign_once(&raw->output, value, "--output", diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        continue;
      }

      inline_value = cmaper_cli_inline_value(arg, "--view");
      if (strcmp(arg, "--view") == 0 || inline_value != NULL) {
        rc = cmaper_cli_take_option_value(argc, argv, &i, "--view",
                                          inline_value, &value, diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        rc = cmaper_cli_assign_once(&raw->view, value, "--view", diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        continue;
      }

      inline_value = cmaper_cli_inline_value(arg, "--limit");
      if (strcmp(arg, "--limit") == 0 || inline_value != NULL) {
        rc = cmaper_cli_take_option_value(argc, argv, &i, "--limit",
                                          inline_value, &value, diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        rc = cmaper_cli_assign_once(&raw->limit, value, "--limit", diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        continue;
      }

      inline_value = cmaper_cli_inline_value(arg, "--window");
      if (strcmp(arg, "--window") == 0 || inline_value != NULL) {
        rc = cmaper_cli_take_option_value(argc, argv, &i, "--window",
                                          inline_value, &value, diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        rc = cmaper_cli_assign_once(&raw->window, value, "--window", diag);
        if (rc != CMAPER_OK) {
          return rc;
        }
        continue;
      }

      if (strcmp(arg, "--changes-only") == 0) {
        raw->changes_only = true;
        continue;
      }

      cmaper_cli_diag_setf(diag, arg, "unknown option '%s'", arg);
      return CMAPER_ERR_CLI_USAGE;
    }

    if (raw->mode_token == NULL) {
      raw->mode_token = arg;
      continue;
    }

    if (raw->positional_count >= CMAPER_CLI_MAX_POSITIONALS) {
      cmaper_cli_diag_set(diag, arg, "too many positional arguments");
      return CMAPER_ERR_CLI_USAGE;
    }

    raw->positionals[raw->positional_count++] = arg;
  }

  return CMAPER_OK;
}
