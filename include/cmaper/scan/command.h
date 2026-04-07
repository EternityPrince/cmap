#ifndef CMAPER_SCAN_COMMAND_H
#define CMAPER_SCAN_COMMAND_H

#include <stdbool.h>
#include <stdio.h>

#include "cmaper/core/error.h"
#include "cmaper/runtime/paths.h"
#include "cmaper/scan/plan.h"
#include "cmaper/scan/source_identity.h"

#define CMAPER_SCAN_COMMAND_MAX_ARGS 32
#define CMAPER_SCAN_COMMAND_ARG_CAP 512
#define CMAPER_SCAN_COMMAND_RENDER_CAP 2048
#define CMAPER_SCAN_COMMAND_DIAG_CAP 256

typedef enum {
  CMAPER_DISCOVERY_KIND_HOST_DISCOVERY = 0,
  CMAPER_DISCOVERY_KIND_PORT_SCAN
} cmaper_discovery_kind_t;

typedef enum {
  CMAPER_DISCOVERY_TRANSPORT_TCP_CONNECT = 0,
  CMAPER_DISCOVERY_TRANSPORT_SYN
} cmaper_discovery_transport_t;

typedef enum {
  CMAPER_SPOOF_SUPPRESS_NONE = 0,
  CMAPER_SPOOF_SUPPRESS_DISABLED,
  CMAPER_SPOOF_SUPPRESS_UNPRIVILEGED,
  CMAPER_SPOOF_SUPPRESS_LOOPBACK,
  CMAPER_SPOOF_SUPPRESS_DISCOVERY_PHASE
} cmaper_spoof_suppression_t;

typedef struct {
  const char *field;
  char message[CMAPER_SCAN_COMMAND_DIAG_CAP];
} cmaper_scan_command_diag_t;

typedef struct {
  const char *target_expression;
  char representative_target[CMAPER_SCAN_SOURCE_TARGET_CAP];
  bool target_is_cidr;
  bool no_ping;
  cmaper_discovery_kind_t kind;
  cmaper_discovery_transport_t transport;
  bool use_exact_ports;
  const char *exact_ports;
  int top_ports;
  int timing_template;
  bool spoof_requested;
  bool spoof_applied;
  cmaper_spoof_suppression_t spoof_suppression;
  char spoof_value[CMAPER_SCAN_SOURCE_MAC_CAP];
} cmaper_scan_discovery_plan_t;

typedef struct {
  int argc;
  char arg_data[CMAPER_SCAN_COMMAND_MAX_ARGS][CMAPER_SCAN_COMMAND_ARG_CAP];
  const char *argv[CMAPER_SCAN_COMMAND_MAX_ARGS + 1];
  char rendered[CMAPER_SCAN_COMMAND_RENDER_CAP];
} cmaper_scan_command_t;

void cmaper_scan_command_diag_clear(cmaper_scan_command_diag_t *diag);
void cmaper_scan_command_diag_setf(cmaper_scan_command_diag_t *diag,
                                   const char *field, const char *fmt, ...);

void cmaper_scan_discovery_plan_init(cmaper_scan_discovery_plan_t *plan);
void cmaper_scan_command_init(cmaper_scan_command_t *command);

int cmaper_scan_discovery_default_top_ports(cmaper_scan_profile_t profile);

cmaper_err_t
cmaper_scan_discovery_plan_build(const cmaper_scan_plan_t *scan_plan,
                                 const cmaper_scan_source_identity_t *identity,
                                 cmaper_scan_discovery_plan_t *discovery_plan,
                                 cmaper_scan_command_diag_t *diag);

cmaper_err_t cmaper_scan_command_build_discovery(
    const cmaper_runtime_paths_t *paths,
    const cmaper_scan_discovery_plan_t *discovery_plan,
    cmaper_scan_command_t *command, cmaper_scan_command_diag_t *diag);

void cmaper_scan_command_render(FILE *stream,
                                const cmaper_scan_command_t *command);

const char *cmaper_discovery_kind_name(cmaper_discovery_kind_t kind);
const char *
cmaper_discovery_transport_name(cmaper_discovery_transport_t transport);
const char *
cmaper_spoof_suppression_name(cmaper_spoof_suppression_t suppression);

#endif
