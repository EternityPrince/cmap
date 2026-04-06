#ifndef CMAPER_SCAN_SOURCE_IDENTITY_H
#define CMAPER_SCAN_SOURCE_IDENTITY_H

#include <stdbool.h>

#include "cmaper/core/error.h"
#include "cmaper/scan/plan.h"

#define CMAPER_SCAN_SOURCE_TARGET_CAP 256
#define CMAPER_SCAN_SOURCE_IFACE_CAP 64
#define CMAPER_SCAN_SOURCE_MAC_CAP 32

typedef enum {
    CMAPER_SCAN_SOURCE_IDENTITY_UNSET = 0,
    CMAPER_SCAN_SOURCE_IDENTITY_FALLBACK
} cmaper_scan_source_identity_mode_t;

typedef struct {
    cmaper_scan_source_identity_mode_t mode;
    char representative_target[CMAPER_SCAN_SOURCE_TARGET_CAP];
    bool representative_is_cidr;
    bool representative_is_loopback;
    bool has_interface;
    char interface_name[CMAPER_SCAN_SOURCE_IFACE_CAP];
    bool has_real_mac;
    char real_mac[CMAPER_SCAN_SOURCE_MAC_CAP];
    bool spoof_requested;
    bool spoof_is_random;
    bool has_spoofed_mac;
    char spoofed_mac[CMAPER_SCAN_SOURCE_MAC_CAP];
} cmaper_scan_source_identity_t;

void cmaper_scan_source_identity_init(cmaper_scan_source_identity_t *identity);

cmaper_err_t cmaper_scan_source_identity_resolve(
    const cmaper_scan_plan_t *plan,
    cmaper_scan_source_identity_t *identity
);

const char *cmaper_scan_source_identity_mode_name(cmaper_scan_source_identity_mode_t mode);

#endif
