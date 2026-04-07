#ifndef CMAPER_HISTORY_QUERY_H
#define CMAPER_HISTORY_QUERY_H

#include <stdbool.h>
#include <stddef.h>

#include <sqlite3.h>

#include "cmaper/core/error.h"
#include "cmaper/history/domain.h"

typedef struct {
  sqlite3_int64 id;
  bool found;
  char session_uid[CMAPER_HISTORY_ID_CAP];
  char status[CMAPER_HISTORY_STATUS_CAP];
  char started_at[CMAPER_HISTORY_TIMESTAMP_CAP];
  char completed_at[CMAPER_HISTORY_TIMESTAMP_CAP];
} cmaper_history_session_ref_t;

typedef struct {
  bool has_window_days;
  int window_days;
  bool changes_only;
} cmaper_history_device_query_options_t;

typedef struct {
  char protocol[CMAPER_HISTORY_PROTOCOL_CAP];
  int port;
} cmaper_history_port_signal_t;

typedef struct {
  char kind[CMAPER_HISTORY_KIND_CAP];
  char value[CMAPER_HISTORY_DETAIL_CAP];
  bool has_service_context;
  char protocol[CMAPER_HISTORY_PROTOCOL_CAP];
  int port;
} cmaper_history_fingerprint_signal_t;

typedef struct {
  char script_id[CMAPER_HISTORY_KEY_CAP];
  char output[CMAPER_HISTORY_DETAIL_CAP];
  bool has_service_context;
  char protocol[CMAPER_HISTORY_PROTOCOL_CAP];
  int port;
} cmaper_history_script_result_signal_t;

typedef struct {
  char key[CMAPER_HISTORY_KEY_CAP];
  char severity[CMAPER_HISTORY_SEVERITY_CAP];
  char state[CMAPER_HISTORY_STATE_CAP];
  char title[CMAPER_HISTORY_TEXT_CAP];
  bool has_service_context;
  char protocol[CMAPER_HISTORY_PROTOCOL_CAP];
  int port;
} cmaper_history_finding_signal_t;

typedef struct {
  char type[CMAPER_HISTORY_KIND_CAP];
  char detail[CMAPER_HISTORY_TEXT_CAP];
  bool has_service_context;
  char protocol[CMAPER_HISTORY_PROTOCOL_CAP];
  int port;
} cmaper_history_surface_signal_t;

typedef struct {
  sqlite3_int64 host_observation_id;
  sqlite3_int64 device_db_id;
  char device_id[CMAPER_HISTORY_ID_CAP];
  char primary_ip[CMAPER_HISTORY_IP_CAP];
  char mac_address[CMAPER_HISTORY_MAC_CAP];
  char hostname[CMAPER_HISTORY_TEXT_CAP];
  char status[CMAPER_HISTORY_STATUS_CAP];
  cmaper_history_port_signal_t *ports;
  size_t port_count;
  cmaper_history_fingerprint_signal_t *fingerprints;
  size_t fingerprint_count;
  cmaper_history_script_result_signal_t *script_results;
  size_t script_result_count;
  cmaper_history_finding_signal_t *findings;
  size_t finding_count;
  cmaper_history_surface_signal_t *surfaces;
  size_t surface_count;
} cmaper_history_host_snapshot_t;

void cmaper_history_session_ref_init(cmaper_history_session_ref_t *ref);
void cmaper_history_host_snapshot_init(
    cmaper_history_host_snapshot_t *snapshot);
void cmaper_history_host_snapshot_dispose(
    cmaper_history_host_snapshot_t *snapshot);
void cmaper_history_host_snapshots_dispose(
    cmaper_history_host_snapshot_t *items, size_t count);

cmaper_err_t cmaper_history_query_open_db(const char *db_path, sqlite3 **out_db,
                                          bool *out_db_available);
void cmaper_history_query_close_db(sqlite3 **db);

cmaper_err_t
cmaper_history_query_resolve_session(sqlite3 *db, const char *session_token,
                                     cmaper_history_session_ref_t *out_ref);

cmaper_err_t cmaper_history_query_resolve_device(sqlite3 *db,
                                                 const char *device_token,
                                                 sqlite3_int64 *out_device_id);

cmaper_err_t
cmaper_history_query_sessions(sqlite3 *db, int limit,
                              cmaper_history_sessions_report_t *out_report);

cmaper_err_t cmaper_history_query_session_detail(
    sqlite3 *db, const cmaper_history_session_ref_t *session_ref,
    cmaper_history_session_report_t *out_report);

cmaper_err_t cmaper_history_query_devices(
    sqlite3 *db, const cmaper_history_session_ref_t *session_ref, int limit,
    cmaper_history_devices_report_t *out_report);

cmaper_err_t cmaper_history_query_device(
    sqlite3 *db, const cmaper_history_session_ref_t *session_ref,
    sqlite3_int64 device_id,
    const cmaper_history_device_query_options_t *options,
    cmaper_history_device_report_t *out_report);

cmaper_err_t
cmaper_history_query_timeline(sqlite3 *db,
                              const cmaper_history_session_ref_t *anchor_ref,
                              sqlite3_int64 device_id, int limit,
                              cmaper_history_timeline_report_t *out_report);

cmaper_err_t
cmaper_history_query_host_snapshots(sqlite3 *db, sqlite3_int64 session_id,
                                    cmaper_history_host_snapshot_t **out_items,
                                    size_t *out_count);

cmaper_err_t cmaper_history_query_posture_counters(
    sqlite3 *db, sqlite3_int64 session_id, sqlite3_int64 device_id,
    cmaper_history_posture_counters_t *out_counters);

cmaper_err_t cmaper_history_query_previous_completed_session(
    sqlite3 *db, sqlite3_int64 anchor_session_id,
    cmaper_history_session_ref_t *out_previous);

#endif
