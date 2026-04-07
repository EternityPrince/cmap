#ifndef CMAPER_SCAN_OPTIONS_H
#define CMAPER_SCAN_OPTIONS_H

#include <stdbool.h>

typedef enum {
  CMAPER_SCAN_PROFILE_UNSET = 0,
  CMAPER_SCAN_PROFILE_LOW,
  CMAPER_SCAN_PROFILE_MID,
  CMAPER_SCAN_PROFILE_HIGH
} cmaper_scan_profile_t;

typedef enum {
  CMAPER_SCAN_TOGGLE_UNSET = 0,
  CMAPER_SCAN_TOGGLE_ENABLE,
  CMAPER_SCAN_TOGGLE_DISABLE
} cmaper_scan_toggle_t;

typedef struct {
  const char *target;
  cmaper_scan_profile_t profile;
  const char *exact_ports;
  cmaper_scan_toggle_t all_ports;
  cmaper_scan_toggle_t no_ping;
  bool has_timing_template;
  int timing_template;
  bool has_detail_workers;
  int detail_workers;
  cmaper_scan_toggle_t service_detection;
  cmaper_scan_toggle_t os_detection;
  cmaper_scan_toggle_t sudo;
  cmaper_scan_toggle_t spoof_mac;
  const char *spoof_mac_value;
  cmaper_scan_toggle_t traceroute;
  cmaper_scan_toggle_t udp_enrichment;
} cmaper_scan_options_t;

void cmaper_scan_options_init(cmaper_scan_options_t *options);
cmaper_scan_profile_t cmaper_scan_profile_from_token(const char *token);
const char *cmaper_scan_profile_name(cmaper_scan_profile_t profile);
const char *cmaper_scan_toggle_name(cmaper_scan_toggle_t toggle);

#endif
