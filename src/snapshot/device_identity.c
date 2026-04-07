#include "cmaper/snapshot/internal/device_identity_internal.h"

#include <ctype.h>
#include <stdio.h>

void cmaper_snapshot_normalize_mac(const char *value, char *out,
                                   size_t out_cap) {
  size_t i;

  if (out == NULL || out_cap == 0) {
    return;
  }

  out[0] = '\0';
  if (value == NULL || value[0] == '\0') {
    return;
  }

  if (snprintf(out, out_cap, "%s", value) >= (int)out_cap) {
    out[0] = '\0';
    return;
  }

  for (i = 0; out[i] != '\0'; ++i) {
    unsigned char ch = (unsigned char)out[i];
    if (ch == '-') {
      out[i] = ':';
    } else {
      out[i] = (char)toupper(ch);
    }
  }
}

void cmaper_snapshot_make_keys(const char *primary_ip, const char *mac_address,
                               char *out_stable_key, size_t stable_cap,
                               char *out_fallback_key, size_t fallback_cap) {
  if (out_stable_key != NULL && stable_cap > 0) {
    out_stable_key[0] = '\0';
  }
  if (out_fallback_key != NULL && fallback_cap > 0) {
    out_fallback_key[0] = '\0';
  }

  if (out_fallback_key != NULL && fallback_cap > 0) {
    if (primary_ip != NULL && primary_ip[0] != '\0') {
      snprintf(out_fallback_key, fallback_cap, "ip:%s", primary_ip);
    } else {
      snprintf(out_fallback_key, fallback_cap, "unknown");
    }
  }

  if (out_stable_key != NULL && stable_cap > 0) {
    if (mac_address != NULL && mac_address[0] != '\0') {
      snprintf(out_stable_key, stable_cap, "mac:%s", mac_address);
    } else if (out_fallback_key != NULL && out_fallback_key[0] != '\0') {
      snprintf(out_stable_key, stable_cap, "%s", out_fallback_key);
    } else {
      snprintf(out_stable_key, stable_cap, "unknown");
    }
  }
}
