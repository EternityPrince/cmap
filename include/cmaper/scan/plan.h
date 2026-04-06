#ifndef CMAPER_SCAN_PLAN_H
#define CMAPER_SCAN_PLAN_H

#include <stdbool.h>
#include <stdio.h>

#include "cmaper/core/error.h"
#include "cmaper/scan/options.h"

#define CMAPER_SCAN_PLAN_DIAG_CAP 256

typedef enum {
    CMAPER_SCAN_SPOOF_MAC_OFF = 0,
    CMAPER_SCAN_SPOOF_MAC_RANDOM,
    CMAPER_SCAN_SPOOF_MAC_CUSTOM
} cmaper_scan_spoof_mac_mode_t;

typedef struct {
    bool exact_ports;
    bool all_ports;
    bool no_ping;
    bool service_detection;
    bool os_detection;
    bool spoof_mac;
    bool traceroute;
    bool udp_enrichment;
    bool privileged_required;
} cmaper_scan_capabilities_t;

typedef struct {
    const char *target;
    cmaper_scan_profile_t profile;
    const char *exact_ports;
    bool all_ports;
    bool no_ping;
    int timing_template;
    int detail_workers;
    bool service_detection;
    bool os_detection;
    bool sudo;
    cmaper_scan_spoof_mac_mode_t spoof_mac_mode;
    const char *spoof_mac_value;
    bool traceroute;
    bool udp_enrichment;
    cmaper_scan_capabilities_t capabilities;
} cmaper_scan_plan_t;

typedef struct {
    const char *field;
    char message[CMAPER_SCAN_PLAN_DIAG_CAP];
} cmaper_scan_plan_diag_t;

void cmaper_scan_plan_diag_clear(cmaper_scan_plan_diag_t *diag);
void cmaper_scan_plan_diag_setf(
    cmaper_scan_plan_diag_t *diag,
    const char *field,
    const char *fmt,
    ...
);

void cmaper_scan_plan_init(cmaper_scan_plan_t *plan);
void cmaper_scan_plan_apply_defaults(cmaper_scan_plan_t *plan);
void cmaper_scan_plan_apply_profile_policy(cmaper_scan_plan_t *plan, cmaper_scan_profile_t profile);
cmaper_err_t cmaper_scan_plan_validate(
    const cmaper_scan_plan_t *plan,
    cmaper_scan_plan_diag_t *diag
);
void cmaper_scan_plan_compute_capabilities(cmaper_scan_plan_t *plan);
cmaper_err_t cmaper_scan_plan_normalize(
    cmaper_scan_plan_t *plan,
    const cmaper_scan_options_t *options,
    cmaper_scan_plan_diag_t *diag
);
void cmaper_scan_plan_render_summary(FILE *stream, const cmaper_scan_plan_t *plan);

#endif
