#include "cmaper/history/alerts.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static cmaper_err_t cmaper_history_append_alert(
    cmaper_history_alert_t **items,
    size_t *count,
    const char *severity,
    const char *code,
    const char *title,
    const char *detail,
    const char *host_key
) {
    cmaper_history_alert_t *next;
    cmaper_history_alert_t *slot;

    if (items == NULL || count == NULL || severity == NULL || code == NULL || title == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    next = (cmaper_history_alert_t *) realloc(
        *items,
        (*count + 1U) * sizeof(cmaper_history_alert_t)
    );
    if (next == NULL) {
        return CMAPER_ERR_OOM;
    }

    *items = next;
    slot = &(*items)[*count];
    cmaper_history_alert_init(slot);

    (void) snprintf(slot->severity, sizeof(slot->severity), "%s", severity);
    (void) snprintf(slot->code, sizeof(slot->code), "%s", code);
    (void) snprintf(slot->title, sizeof(slot->title), "%s", title);
    if (detail != NULL) {
        (void) snprintf(slot->detail, sizeof(slot->detail), "%s", detail);
    }
    if (host_key != NULL) {
        (void) snprintf(slot->host_key, sizeof(slot->host_key), "%s", host_key);
    }

    *count += 1U;
    return CMAPER_OK;
}

static void cmaper_history_clear_alerts(cmaper_history_alert_t **items, size_t *count) {
    if (items == NULL || count == NULL) {
        return;
    }

    if (*items != NULL) {
        free(*items);
    }
    *items = NULL;
    *count = 0;
}

cmaper_err_t cmaper_history_alerts_build_for_diff(cmaper_history_diff_report_t *report) {
    cmaper_err_t rc;
    size_t i;

    if (report == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    cmaper_history_clear_alerts(&report->alerts, &report->alert_count);

    if (!report->from_found || !report->to_found) {
        return CMAPER_OK;
    }

    if (report->summary.findings_high_opened > 0) {
        char detail[CMAPER_HISTORY_DETAIL_CAP];
        (void) snprintf(
            detail,
            sizeof(detail),
            "Opened %zu high/critical findings between sessions",
            report->summary.findings_high_opened
        );
        rc = cmaper_history_append_alert(
            &report->alerts,
            &report->alert_count,
            "critical",
            "new-high-findings",
            "New high-severity findings detected",
            detail,
            NULL
        );
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    if (report->summary.findings_opened > report->summary.findings_resolved
        && report->summary.findings_opened > 0) {
        char detail[CMAPER_HISTORY_DETAIL_CAP];
        (void) snprintf(
            detail,
            sizeof(detail),
            "Opened findings (%zu) exceed resolved findings (%zu)",
            report->summary.findings_opened,
            report->summary.findings_resolved
        );
        rc = cmaper_history_append_alert(
            &report->alerts,
            &report->alert_count,
            "warn",
            "finding-drift-up",
            "Security drift increased",
            detail,
            NULL
        );
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    for (i = 0; i < report->changed_host_count; ++i) {
        const cmaper_history_changed_host_t *host = &report->changed_hosts[i];
        if (report->alert_count >= 64U) {
            break;
        }

        if (host->findings_high_opened > 0) {
            char detail[CMAPER_HISTORY_DETAIL_CAP];
            (void) snprintf(
                detail,
                sizeof(detail),
                "%s opened %zu high/critical findings",
                host->host_key,
                host->findings_high_opened
            );
            rc = cmaper_history_append_alert(
                &report->alerts,
                &report->alert_count,
                "critical",
                "host-high-findings-opened",
                "Host introduced high-risk findings",
                detail,
                host->host_key
            );
            if (rc != CMAPER_OK) {
                return rc;
            }
        }

        if (host->risky_surfaces_added > 0) {
            char detail[CMAPER_HISTORY_DETAIL_CAP];
            (void) snprintf(
                detail,
                sizeof(detail),
                "%s added %zu risky management surfaces",
                host->host_key,
                host->risky_surfaces_added
            );
            rc = cmaper_history_append_alert(
                &report->alerts,
                &report->alert_count,
                "high",
                "host-risky-surface-added",
                "New risky management surface detected",
                detail,
                host->host_key
            );
            if (rc != CMAPER_OK) {
                return rc;
            }
        }

        if (cmaper_history_host_reason_has(host->reason_mask, CMAPER_HISTORY_HOST_REASON_MOVED)
            && host->to_high_findings_open > 0) {
            char detail[CMAPER_HISTORY_DETAIL_CAP];
            (void) snprintf(
                detail,
                sizeof(detail),
                "%s moved to a new IP and still has %zu high-risk open findings",
                host->host_key,
                host->to_high_findings_open
            );
            rc = cmaper_history_append_alert(
                &report->alerts,
                &report->alert_count,
                "high",
                "moved-risky-host",
                "Risky host changed IP",
                detail,
                host->host_key
            );
            if (rc != CMAPER_OK) {
                return rc;
            }
        }

        if (cmaper_history_host_reason_has(host->reason_mask, CMAPER_HISTORY_HOST_REASON_REMOVED)
            && host->from_high_findings_open > 0) {
            char detail[CMAPER_HISTORY_DETAIL_CAP];
            (void) snprintf(
                detail,
                sizeof(detail),
                "%s disappeared while previously carrying %zu high-risk open findings",
                host->host_key,
                host->from_high_findings_open
            );
            rc = cmaper_history_append_alert(
                &report->alerts,
                &report->alert_count,
                "warn",
                "removed-risky-host",
                "Previously risky host disappeared",
                detail,
                host->host_key
            );
            if (rc != CMAPER_OK) {
                return rc;
            }
        }
    }

    return CMAPER_OK;
}

cmaper_err_t cmaper_history_alerts_build_for_posture(cmaper_history_posture_report_t *report) {
    cmaper_err_t rc;

    if (report == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    cmaper_history_clear_alerts(&report->alerts, &report->alert_count);
    if (!report->session_found) {
        return CMAPER_OK;
    }

    if (report->counters.findings_high_or_worse > 0) {
        char detail[CMAPER_HISTORY_DETAIL_CAP];
        (void) snprintf(
            detail,
            sizeof(detail),
            "Session has %zu open high/critical findings",
            report->counters.findings_high_or_worse
        );
        rc = cmaper_history_append_alert(
            &report->alerts,
            &report->alert_count,
            "high",
            "posture-high-findings",
            "High-risk findings remain open",
            detail,
            NULL
        );
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    if (report->counters.management_surfaces_total > 0) {
        char detail[CMAPER_HISTORY_DETAIL_CAP];
        (void) snprintf(
            detail,
            sizeof(detail),
            "%zu management surfaces across %zu hosts",
            report->counters.management_surfaces_total,
            report->counters.hosts_with_management_surfaces
        );
        rc = cmaper_history_append_alert(
            &report->alerts,
            &report->alert_count,
            "warn",
            "posture-management-surface",
            "Management surfaces are exposed",
            detail,
            NULL
        );
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    if (report->drift.has_previous && report->drift.findings_high_or_worse_delta > 0) {
        char detail[CMAPER_HISTORY_DETAIL_CAP];
        (void) snprintf(
            detail,
            sizeof(detail),
            "High/critical open findings increased by %+ld vs %s",
            report->drift.findings_high_or_worse_delta,
            report->drift.previous_session_id
        );
        rc = cmaper_history_append_alert(
            &report->alerts,
            &report->alert_count,
            "high",
            "posture-drift-high-findings",
            "High-risk drift increased",
            detail,
            NULL
        );
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    if (report->drift.has_previous && report->drift.management_surfaces_total_delta > 0) {
        char detail[CMAPER_HISTORY_DETAIL_CAP];
        (void) snprintf(
            detail,
            sizeof(detail),
            "Management surfaces increased by %+ld vs %s",
            report->drift.management_surfaces_total_delta,
            report->drift.previous_session_id
        );
        rc = cmaper_history_append_alert(
            &report->alerts,
            &report->alert_count,
            "warn",
            "posture-drift-management",
            "Management exposure drift increased",
            detail,
            NULL
        );
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    if (report->drift.risk_increased) {
        rc = cmaper_history_append_alert(
            &report->alerts,
            &report->alert_count,
            "warn",
            "posture-risk-increased",
            "Overall posture drift indicates higher risk",
            "At least one high-signal risk counter increased compared to previous completed session",
            NULL
        );
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    return CMAPER_OK;
}
