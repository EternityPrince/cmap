#include "cmaper/snapshot/internal/device_internal.h"

#include "cmaper/scan/source_identity.h"
#include "cmaper/snapshot/internal/device_identity_internal.h"
#include "cmaper/snapshot/internal/device_lookup_internal.h"
#include "cmaper/snapshot/internal/device_upsert_internal.h"

#define CMAPER_SNAPSHOT_KEY_CAP 160

cmaper_err_t
cmaper_snapshot_resolve_device(sqlite3 *db, sqlite3_int64 session_id,
                               const char *primary_ip, const char *address_type,
                               const char *mac_address, const char *mac_vendor,
                               sqlite3_int64 *out_device_id) {
  char normalized_mac[CMAPER_SCAN_SOURCE_MAC_CAP];
  char stable_key[CMAPER_SNAPSHOT_KEY_CAP];
  char fallback_key[CMAPER_SNAPSHOT_KEY_CAP];
  sqlite3_int64 device_id = 0;
  cmaper_err_t rc;

  if (db == NULL || primary_ip == NULL || primary_ip[0] == '\0' ||
      out_device_id == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  *out_device_id = 0;

  cmaper_snapshot_normalize_mac(mac_address, normalized_mac,
                                sizeof(normalized_mac));
  cmaper_snapshot_make_keys(
      primary_ip, normalized_mac[0] != '\0' ? normalized_mac : NULL, stable_key,
      sizeof(stable_key), fallback_key, sizeof(fallback_key));

  if (normalized_mac[0] != '\0') {
    rc = cmaper_snapshot_find_device_by_mac(db, normalized_mac, &device_id);
    if (rc != CMAPER_OK) {
      return rc;
    }
  }

  if (device_id <= 0) {
    rc = cmaper_snapshot_find_device_by_previous_ip(db, primary_ip, &device_id);
    if (rc != CMAPER_OK) {
      return rc;
    }
  }

  if (device_id <= 0) {
    rc = cmaper_snapshot_find_device_by_fallback_key(db, fallback_key,
                                                     &device_id);
    if (rc != CMAPER_OK) {
      return rc;
    }
  }

  if (device_id <= 0) {
    rc = cmaper_snapshot_insert_device(
        db, stable_key, fallback_key,
        normalized_mac[0] != '\0' ? normalized_mac : NULL, mac_vendor,
        session_id, &device_id);
    if (rc != CMAPER_OK) {
      return rc;
    }
  } else {
    rc = cmaper_snapshot_update_device(
        db, device_id, session_id,
        normalized_mac[0] != '\0' ? normalized_mac : NULL, mac_vendor);
    if (rc != CMAPER_OK) {
      return rc;
    }
  }

  rc = cmaper_snapshot_upsert_device_ip(db, device_id, primary_ip, address_type,
                                        session_id);
  if (rc != CMAPER_OK) {
    return rc;
  }

  *out_device_id = device_id;
  return CMAPER_OK;
}
