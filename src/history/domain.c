#include "cmaper/history/domain.h"

#include <stdlib.h>

static void cmaper_history_zero_bytes(void *ptr, size_t size) {
    unsigned char *bytes = (unsigned char *) ptr;
    size_t i;

    if (ptr == NULL) {
        return;
    }

    for (i = 0; i < size; ++i) {
        bytes[i] = 0U;
    }
}

void cmaper_history_session_row_init(cmaper_history_session_row_t *row) {
    cmaper_history_zero_bytes(row, sizeof(*row));
}

void cmaper_history_session_host_row_init(cmaper_history_session_host_row_t *row) {
    cmaper_history_zero_bytes(row, sizeof(*row));
}

void cmaper_history_device_row_init(cmaper_history_device_row_t *row) {
    cmaper_history_zero_bytes(row, sizeof(*row));
}

void cmaper_history_device_ip_row_init(cmaper_history_device_ip_row_t *row) {
    cmaper_history_zero_bytes(row, sizeof(*row));
}

void cmaper_history_device_observation_row_init(cmaper_history_device_observation_row_t *row) {
    cmaper_history_zero_bytes(row, sizeof(*row));
}

void cmaper_history_timeline_row_init(cmaper_history_timeline_row_t *row) {
    cmaper_history_zero_bytes(row, sizeof(*row));
}

void cmaper_history_changed_host_init(cmaper_history_changed_host_t *row) {
    cmaper_history_zero_bytes(row, sizeof(*row));
}

void cmaper_history_alert_init(cmaper_history_alert_t *alert) {
    cmaper_history_zero_bytes(alert, sizeof(*alert));
}

void cmaper_history_posture_counters_init(cmaper_history_posture_counters_t *counters) {
    cmaper_history_zero_bytes(counters, sizeof(*counters));
}

void cmaper_history_posture_drift_init(cmaper_history_posture_drift_t *drift) {
    cmaper_history_zero_bytes(drift, sizeof(*drift));
}

void cmaper_history_sessions_report_init(cmaper_history_sessions_report_t *report) {
    if (report == NULL) {
        return;
    }

    report->db_available = false;
    report->limit = 0;
    report->total_sessions = 0;
    report->truncated = false;
    report->items = NULL;
    report->count = 0;
}

void cmaper_history_sessions_report_dispose(cmaper_history_sessions_report_t *report) {
    if (report == NULL) {
        return;
    }

    if (report->items != NULL) {
        free(report->items);
    }
    cmaper_history_sessions_report_init(report);
}

void cmaper_history_session_report_init(cmaper_history_session_report_t *report) {
    if (report == NULL) {
        return;
    }

    report->db_available = false;
    report->found = false;
    cmaper_history_session_row_init(&report->summary);
    report->hosts = NULL;
    report->host_count = 0;
}

void cmaper_history_session_report_dispose(cmaper_history_session_report_t *report) {
    if (report == NULL) {
        return;
    }

    if (report->hosts != NULL) {
        free(report->hosts);
    }
    cmaper_history_session_report_init(report);
}

void cmaper_history_devices_report_init(cmaper_history_devices_report_t *report) {
    if (report == NULL) {
        return;
    }

    report->db_available = false;
    report->session_found = false;
    report->session_id[0] = '\0';
    report->limit = 0;
    report->total_devices = 0;
    report->truncated = false;
    report->items = NULL;
    report->count = 0;
}

void cmaper_history_devices_report_dispose(cmaper_history_devices_report_t *report) {
    if (report == NULL) {
        return;
    }

    if (report->items != NULL) {
        free(report->items);
    }
    cmaper_history_devices_report_init(report);
}

void cmaper_history_device_report_init(cmaper_history_device_report_t *report) {
    if (report == NULL) {
        return;
    }

    report->db_available = false;
    report->session_found = false;
    report->found = false;
    report->selected_observation_found = false;
    report->session_id[0] = '\0';
    report->device_id[0] = '\0';
    report->stable_key[0] = '\0';
    report->fallback_key[0] = '\0';
    report->mac_address[0] = '\0';
    report->mac_vendor[0] = '\0';
    report->first_seen_session_id[0] = '\0';
    report->last_seen_session_id[0] = '\0';
    report->selected_primary_ip[0] = '\0';
    report->selected_hostname[0] = '\0';
    report->selected_status[0] = '\0';
    report->selected_open_tcp_ports = 0;
    report->selected_findings_open = 0;
    report->selected_findings_high_or_worse = 0;
    report->selected_management_surfaces = 0;
    report->ip_addresses = NULL;
    report->ip_address_count = 0;
    report->observations = NULL;
    report->observation_count = 0;
}

void cmaper_history_device_report_dispose(cmaper_history_device_report_t *report) {
    if (report == NULL) {
        return;
    }

    if (report->ip_addresses != NULL) {
        free(report->ip_addresses);
    }
    if (report->observations != NULL) {
        free(report->observations);
    }
    cmaper_history_device_report_init(report);
}

void cmaper_history_timeline_report_init(cmaper_history_timeline_report_t *report) {
    if (report == NULL) {
        return;
    }

    report->db_available = false;
    report->anchor_found = false;
    report->has_device_filter = false;
    report->anchor_session_id[0] = '\0';
    report->device_id[0] = '\0';
    report->limit = 0;
    report->items = NULL;
    report->count = 0;
}

void cmaper_history_timeline_report_dispose(cmaper_history_timeline_report_t *report) {
    if (report == NULL) {
        return;
    }

    if (report->items != NULL) {
        free(report->items);
    }
    cmaper_history_timeline_report_init(report);
}

void cmaper_history_diff_summary_init(cmaper_history_diff_summary_t *summary) {
    cmaper_history_zero_bytes(summary, sizeof(*summary));
}

void cmaper_history_diff_report_init(cmaper_history_diff_report_t *report) {
    if (report == NULL) {
        return;
    }

    report->db_available = false;
    report->from_found = false;
    report->to_found = false;
    report->from_session_id[0] = '\0';
    report->to_session_id[0] = '\0';
    cmaper_history_diff_summary_init(&report->summary);
    report->changed_hosts = NULL;
    report->changed_host_count = 0;
    report->alerts = NULL;
    report->alert_count = 0;
}

void cmaper_history_diff_report_dispose(cmaper_history_diff_report_t *report) {
    if (report == NULL) {
        return;
    }

    if (report->changed_hosts != NULL) {
        free(report->changed_hosts);
    }
    if (report->alerts != NULL) {
        free(report->alerts);
    }
    cmaper_history_diff_report_init(report);
}

void cmaper_history_posture_report_init(cmaper_history_posture_report_t *report) {
    if (report == NULL) {
        return;
    }

    report->db_available = false;
    report->session_found = false;
    report->has_device_filter = false;
    report->session_id[0] = '\0';
    report->device_id[0] = '\0';
    report->session_status[0] = '\0';
    report->started_at[0] = '\0';
    report->completed_at[0] = '\0';
    cmaper_history_posture_counters_init(&report->counters);
    cmaper_history_posture_drift_init(&report->drift);
    report->alerts = NULL;
    report->alert_count = 0;
}

void cmaper_history_posture_report_dispose(cmaper_history_posture_report_t *report) {
    if (report == NULL) {
        return;
    }

    if (report->alerts != NULL) {
        free(report->alerts);
    }
    cmaper_history_posture_report_init(report);
}
