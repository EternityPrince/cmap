#ifndef CMAPER_SNAPSHOT_DEVICE_IDENTITY_INTERNAL_H
#define CMAPER_SNAPSHOT_DEVICE_IDENTITY_INTERNAL_H

#include <stddef.h>

void cmaper_snapshot_normalize_mac(const char *value, char *out,
                                   size_t out_cap);

void cmaper_snapshot_make_keys(const char *primary_ip, const char *mac_address,
                               char *out_stable_key, size_t stable_cap,
                               char *out_fallback_key, size_t fallback_cap);

#endif
