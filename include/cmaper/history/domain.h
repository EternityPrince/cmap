#ifndef CMAPER_HISTORY_DOMAIN_H
#define CMAPER_HISTORY_DOMAIN_H

#include <stdbool.h>
#include <stddef.h>

#define CMAPER_HISTORY_ID_CAP 96
#define CMAPER_HISTORY_STATUS_CAP 24
#define CMAPER_HISTORY_PROFILE_CAP 16
#define CMAPER_HISTORY_TARGET_CAP 256
#define CMAPER_HISTORY_TIMESTAMP_CAP 40
#define CMAPER_HISTORY_IP_CAP 64
#define CMAPER_HISTORY_MAC_CAP 64
#define CMAPER_HISTORY_VENDOR_CAP 128
#define CMAPER_HISTORY_TEXT_CAP 256
#define CMAPER_HISTORY_DETAIL_CAP 512
#define CMAPER_HISTORY_KEY_CAP 160
#define CMAPER_HISTORY_KIND_CAP 16
#define CMAPER_HISTORY_PROTOCOL_CAP 8
#define CMAPER_HISTORY_SEVERITY_CAP 16
#define CMAPER_HISTORY_STATE_CAP 16
#define CMAPER_HISTORY_ALERT_CODE_CAP 64
#define CMAPER_HISTORY_ALERT_TITLE_CAP 160
#define CMAPER_HISTORY_CHANGE_TYPE_CAP 48

typedef enum {
  CMAPER_HISTORY_HOST_REASON_NONE = 0U,
  CMAPER_HISTORY_HOST_REASON_ADDED = 1U << 0,
  CMAPER_HISTORY_HOST_REASON_REMOVED = 1U << 1,
  CMAPER_HISTORY_HOST_REASON_MOVED = 1U << 2,
  CMAPER_HISTORY_HOST_REASON_STATUS_CHANGED = 1U << 3,
  CMAPER_HISTORY_HOST_REASON_HOSTNAME_CHANGED = 1U << 4,
  CMAPER_HISTORY_HOST_REASON_MAC_CHANGED = 1U << 5,
  CMAPER_HISTORY_HOST_REASON_PORTS_CHANGED = 1U << 6,
  CMAPER_HISTORY_HOST_REASON_FINGERPRINTS_CHANGED = 1U << 7,
  CMAPER_HISTORY_HOST_REASON_FINDINGS_CHANGED = 1U << 8,
  CMAPER_HISTORY_HOST_REASON_MANAGEMENT_CHANGED = 1U << 9
} cmaper_history_host_reason_t;

typedef struct {
  char session_id[CMAPER_HISTORY_ID_CAP];
  char status[CMAPER_HISTORY_STATUS_CAP];
  char target[CMAPER_HISTORY_TARGET_CAP];
  char profile[CMAPER_HISTORY_PROFILE_CAP];
  char started_at[CMAPER_HISTORY_TIMESTAMP_CAP];
  char completed_at[CMAPER_HISTORY_TIMESTAMP_CAP];
  int detail_targets_total;
  int detail_hosts_success;
  int detail_hosts_failed;
  int detail_hosts_degraded;
  size_t host_count;
  size_t findings_total;
  size_t findings_open;
  size_t findings_high_or_worse;
  size_t management_surfaces_total;
} cmaper_history_session_row_t;

typedef struct {
  char device_id[CMAPER_HISTORY_ID_CAP];
  char primary_ip[CMAPER_HISTORY_IP_CAP];
  char status[CMAPER_HISTORY_STATUS_CAP];
  char hostname[CMAPER_HISTORY_TEXT_CAP];
  char mac_address[CMAPER_HISTORY_MAC_CAP];
  char mac_vendor[CMAPER_HISTORY_VENDOR_CAP];
  char open_tcp_list[CMAPER_HISTORY_DETAIL_CAP];
  char scripts_used[CMAPER_HISTORY_DETAIL_CAP];
  char script_results[CMAPER_HISTORY_DETAIL_CAP];
  char script_signals[CMAPER_HISTORY_DETAIL_CAP];
  char findings_detail[CMAPER_HISTORY_DETAIL_CAP];
  char surfaces_detail[CMAPER_HISTORY_DETAIL_CAP];
  size_t scripts_used_count;
  size_t script_result_count;
  size_t script_signal_count;
  size_t open_tcp_ports;
  size_t findings_open;
  size_t findings_high_or_worse;
  size_t management_surfaces;
} cmaper_history_session_host_row_t;

typedef struct {
  bool db_available;
  int limit;
  size_t total_sessions;
  bool truncated;
  cmaper_history_session_row_t *items;
  size_t count;
} cmaper_history_sessions_report_t;

typedef struct {
  bool db_available;
  bool found;
  cmaper_history_session_row_t summary;
  cmaper_history_session_host_row_t *hosts;
  size_t host_count;
} cmaper_history_session_report_t;

typedef struct {
  char device_id[CMAPER_HISTORY_ID_CAP];
  char stable_key[CMAPER_HISTORY_KEY_CAP];
  char fallback_key[CMAPER_HISTORY_KEY_CAP];
  char mac_address[CMAPER_HISTORY_MAC_CAP];
  char mac_vendor[CMAPER_HISTORY_VENDOR_CAP];
  char primary_ip[CMAPER_HISTORY_IP_CAP];
  char hostname[CMAPER_HISTORY_TEXT_CAP];
  char status[CMAPER_HISTORY_STATUS_CAP];
  size_t host_observations;
  size_t open_tcp_ports;
  size_t findings_open;
  size_t findings_high_or_worse;
  size_t management_surfaces;
} cmaper_history_device_row_t;

typedef struct {
  bool db_available;
  bool session_found;
  char session_id[CMAPER_HISTORY_ID_CAP];
  int limit;
  size_t total_devices;
  bool truncated;
  cmaper_history_device_row_t *items;
  size_t count;
} cmaper_history_devices_report_t;

typedef struct {
  char ip_address[CMAPER_HISTORY_IP_CAP];
  char address_type[CMAPER_HISTORY_STATUS_CAP];
  bool is_current;
  char first_seen_session_id[CMAPER_HISTORY_ID_CAP];
  char last_seen_session_id[CMAPER_HISTORY_ID_CAP];
} cmaper_history_device_ip_row_t;

typedef struct {
  long long host_observation_id;
  char session_id[CMAPER_HISTORY_ID_CAP];
  char started_at[CMAPER_HISTORY_TIMESTAMP_CAP];
  char status[CMAPER_HISTORY_STATUS_CAP];
  char primary_ip[CMAPER_HISTORY_IP_CAP];
  char hostname[CMAPER_HISTORY_TEXT_CAP];
  char host_status[CMAPER_HISTORY_STATUS_CAP];
  size_t open_tcp_ports;
  size_t findings_open;
  size_t findings_high_or_worse;
  size_t management_surfaces;
} cmaper_history_device_observation_row_t;

typedef struct {
  char session_id[CMAPER_HISTORY_ID_CAP];
  char started_at[CMAPER_HISTORY_TIMESTAMP_CAP];
  char event_type[CMAPER_HISTORY_CHANGE_TYPE_CAP];
  char detail[CMAPER_HISTORY_DETAIL_CAP];
} cmaper_history_device_change_event_t;

typedef struct {
  bool db_available;
  bool session_found;
  bool found;
  bool selected_observation_found;
  char session_id[CMAPER_HISTORY_ID_CAP];
  char device_id[CMAPER_HISTORY_ID_CAP];
  char stable_key[CMAPER_HISTORY_KEY_CAP];
  char fallback_key[CMAPER_HISTORY_KEY_CAP];
  char mac_address[CMAPER_HISTORY_MAC_CAP];
  char mac_vendor[CMAPER_HISTORY_VENDOR_CAP];
  char first_seen_session_id[CMAPER_HISTORY_ID_CAP];
  char last_seen_session_id[CMAPER_HISTORY_ID_CAP];
  char selected_primary_ip[CMAPER_HISTORY_IP_CAP];
  char selected_hostname[CMAPER_HISTORY_TEXT_CAP];
  char selected_status[CMAPER_HISTORY_STATUS_CAP];
  size_t selected_open_tcp_ports;
  size_t selected_findings_open;
  size_t selected_findings_high_or_worse;
  size_t selected_management_surfaces;
  bool has_window_days;
  int window_days;
  bool changes_only;
  cmaper_history_device_ip_row_t *ip_addresses;
  size_t ip_address_count;
  cmaper_history_device_observation_row_t *observations;
  size_t observation_count;
  cmaper_history_device_change_event_t *change_events;
  size_t change_event_count;
  bool changes_truncated;
} cmaper_history_device_report_t;

typedef struct {
  char session_id[CMAPER_HISTORY_ID_CAP];
  char status[CMAPER_HISTORY_STATUS_CAP];
  char started_at[CMAPER_HISTORY_TIMESTAMP_CAP];
  char completed_at[CMAPER_HISTORY_TIMESTAMP_CAP];
  size_t hosts_total;
  size_t findings_open;
  size_t findings_high_or_worse;
  size_t management_surfaces;
  bool device_present;
  char device_ip[CMAPER_HISTORY_IP_CAP];
  char device_status[CMAPER_HISTORY_STATUS_CAP];
} cmaper_history_timeline_row_t;

typedef struct {
  bool db_available;
  bool anchor_found;
  bool has_device_filter;
  char anchor_session_id[CMAPER_HISTORY_ID_CAP];
  char device_id[CMAPER_HISTORY_ID_CAP];
  int limit;
  cmaper_history_timeline_row_t *items;
  size_t count;
} cmaper_history_timeline_report_t;

typedef struct {
  size_t hosts_from;
  size_t hosts_to;
  size_t hosts_added;
  size_t hosts_removed;
  size_t hosts_changed;
  size_t hosts_moved;
  size_t hosts_unchanged;
  size_t ports_added;
  size_t ports_removed;
  size_t fingerprints_added;
  size_t fingerprints_removed;
  size_t findings_opened;
  size_t findings_resolved;
  size_t findings_high_opened;
  size_t management_added;
  size_t management_removed;
} cmaper_history_diff_summary_t;

typedef struct {
  char host_key[CMAPER_HISTORY_KEY_CAP];
  char match_strategy[CMAPER_HISTORY_STATUS_CAP];
  char mac_address[CMAPER_HISTORY_MAC_CAP];
  char from_ip[CMAPER_HISTORY_IP_CAP];
  char to_ip[CMAPER_HISTORY_IP_CAP];
  char from_status[CMAPER_HISTORY_STATUS_CAP];
  char to_status[CMAPER_HISTORY_STATUS_CAP];
  char from_hostname[CMAPER_HISTORY_TEXT_CAP];
  char to_hostname[CMAPER_HISTORY_TEXT_CAP];
  unsigned int reason_mask;
  size_t ports_added;
  size_t ports_removed;
  size_t fingerprints_added;
  size_t fingerprints_removed;
  size_t findings_opened;
  size_t findings_resolved;
  size_t findings_high_opened;
  size_t from_high_findings_open;
  size_t to_high_findings_open;
  size_t management_added;
  size_t management_removed;
  size_t risky_surfaces_added;
} cmaper_history_changed_host_t;

typedef struct {
  char severity[CMAPER_HISTORY_SEVERITY_CAP];
  char code[CMAPER_HISTORY_ALERT_CODE_CAP];
  char title[CMAPER_HISTORY_ALERT_TITLE_CAP];
  char detail[CMAPER_HISTORY_DETAIL_CAP];
  char host_key[CMAPER_HISTORY_KEY_CAP];
} cmaper_history_alert_t;

typedef struct {
  bool db_available;
  bool from_found;
  bool to_found;
  char from_session_id[CMAPER_HISTORY_ID_CAP];
  char to_session_id[CMAPER_HISTORY_ID_CAP];
  cmaper_history_diff_summary_t summary;
  cmaper_history_changed_host_t *changed_hosts;
  size_t changed_host_count;
  cmaper_history_alert_t *alerts;
  size_t alert_count;
} cmaper_history_diff_report_t;

typedef struct {
  size_t hosts_total;
  size_t hosts_up;
  size_t devices_total;
  size_t open_tcp_ports;
  size_t findings_total;
  size_t findings_open;
  size_t findings_high_or_worse;
  size_t management_surfaces_total;
  size_t hosts_with_management_surfaces;
} cmaper_history_posture_counters_t;

typedef struct {
  bool has_previous;
  char previous_session_id[CMAPER_HISTORY_ID_CAP];
  long hosts_total_delta;
  long hosts_up_delta;
  long devices_total_delta;
  long open_tcp_ports_delta;
  long findings_total_delta;
  long findings_open_delta;
  long findings_high_or_worse_delta;
  long management_surfaces_total_delta;
  long hosts_with_management_surfaces_delta;
  bool risk_increased;
} cmaper_history_posture_drift_t;

typedef struct {
  bool db_available;
  bool session_found;
  bool has_device_filter;
  char session_id[CMAPER_HISTORY_ID_CAP];
  char device_id[CMAPER_HISTORY_ID_CAP];
  char session_status[CMAPER_HISTORY_STATUS_CAP];
  char started_at[CMAPER_HISTORY_TIMESTAMP_CAP];
  char completed_at[CMAPER_HISTORY_TIMESTAMP_CAP];
  cmaper_history_posture_counters_t counters;
  cmaper_history_posture_drift_t drift;
  cmaper_history_alert_t *alerts;
  size_t alert_count;
} cmaper_history_posture_report_t;

void cmaper_history_session_row_init(cmaper_history_session_row_t *row);
void cmaper_history_session_host_row_init(
    cmaper_history_session_host_row_t *row);
void cmaper_history_device_row_init(cmaper_history_device_row_t *row);
void cmaper_history_device_ip_row_init(cmaper_history_device_ip_row_t *row);
void cmaper_history_device_observation_row_init(
    cmaper_history_device_observation_row_t *row);
void cmaper_history_device_change_event_init(
    cmaper_history_device_change_event_t *event);
void cmaper_history_timeline_row_init(cmaper_history_timeline_row_t *row);
void cmaper_history_changed_host_init(cmaper_history_changed_host_t *row);
void cmaper_history_alert_init(cmaper_history_alert_t *alert);
void cmaper_history_posture_counters_init(
    cmaper_history_posture_counters_t *counters);
void cmaper_history_posture_drift_init(cmaper_history_posture_drift_t *drift);

void cmaper_history_sessions_report_init(
    cmaper_history_sessions_report_t *report);
void cmaper_history_sessions_report_dispose(
    cmaper_history_sessions_report_t *report);
void cmaper_history_session_report_init(
    cmaper_history_session_report_t *report);
void cmaper_history_session_report_dispose(
    cmaper_history_session_report_t *report);
void cmaper_history_devices_report_init(
    cmaper_history_devices_report_t *report);
void cmaper_history_devices_report_dispose(
    cmaper_history_devices_report_t *report);
void cmaper_history_device_report_init(cmaper_history_device_report_t *report);
void cmaper_history_device_report_dispose(
    cmaper_history_device_report_t *report);
void cmaper_history_timeline_report_init(
    cmaper_history_timeline_report_t *report);
void cmaper_history_timeline_report_dispose(
    cmaper_history_timeline_report_t *report);
void cmaper_history_diff_summary_init(cmaper_history_diff_summary_t *summary);
void cmaper_history_diff_report_init(cmaper_history_diff_report_t *report);
void cmaper_history_diff_report_dispose(cmaper_history_diff_report_t *report);
void cmaper_history_posture_report_init(
    cmaper_history_posture_report_t *report);
void cmaper_history_posture_report_dispose(
    cmaper_history_posture_report_t *report);

#endif
