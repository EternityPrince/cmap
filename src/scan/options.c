#include "cmaper/scan/options.h"

#include <stddef.h>
#include <string.h>

void cmaper_scan_options_init(cmaper_scan_options_t *options) {
    if (options == NULL) {
        return;
    }

    options->target = NULL;
    options->profile = CMAPER_SCAN_PROFILE_UNSET;
    options->exact_ports = NULL;
    options->all_ports = CMAPER_SCAN_TOGGLE_UNSET;
    options->no_ping = CMAPER_SCAN_TOGGLE_UNSET;
    options->has_timing_template = false;
    options->timing_template = 0;
    options->has_detail_workers = false;
    options->detail_workers = 0;
    options->service_detection = CMAPER_SCAN_TOGGLE_UNSET;
    options->os_detection = CMAPER_SCAN_TOGGLE_UNSET;
    options->sudo = CMAPER_SCAN_TOGGLE_UNSET;
    options->spoof_mac = CMAPER_SCAN_TOGGLE_UNSET;
    options->spoof_mac_value = NULL;
    options->traceroute = CMAPER_SCAN_TOGGLE_UNSET;
    options->udp_enrichment = CMAPER_SCAN_TOGGLE_UNSET;
}

cmaper_scan_profile_t cmaper_scan_profile_from_token(const char *token) {
    if (token == NULL || token[0] == '\0') {
        return CMAPER_SCAN_PROFILE_UNSET;
    }

    if (strcmp(token, "low") == 0) {
        return CMAPER_SCAN_PROFILE_LOW;
    }

    if (strcmp(token, "mid") == 0) {
        return CMAPER_SCAN_PROFILE_MID;
    }

    if (strcmp(token, "high") == 0) {
        return CMAPER_SCAN_PROFILE_HIGH;
    }

    return CMAPER_SCAN_PROFILE_UNSET;
}

const char *cmaper_scan_profile_name(cmaper_scan_profile_t profile) {
    switch (profile) {
    case CMAPER_SCAN_PROFILE_LOW:
        return "low";
    case CMAPER_SCAN_PROFILE_MID:
        return "mid";
    case CMAPER_SCAN_PROFILE_HIGH:
        return "high";
    case CMAPER_SCAN_PROFILE_UNSET:
        break;
    }

    return "unset";
}

const char *cmaper_scan_toggle_name(cmaper_scan_toggle_t toggle) {
    switch (toggle) {
    case CMAPER_SCAN_TOGGLE_ENABLE:
        return "enable";
    case CMAPER_SCAN_TOGGLE_DISABLE:
        return "disable";
    case CMAPER_SCAN_TOGGLE_UNSET:
        break;
    }

    return "unset";
}
