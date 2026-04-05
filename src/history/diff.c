#include "cmaper/history/diff.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmaper/history/fuzzy.h"

static bool cmaper_history_text_nonempty(const char *value) {
    return value != NULL && value[0] != '\0';
}

static void cmaper_history_copy_string(char *out, size_t out_cap, const char *value) {
    if (out == NULL || out_cap == 0) {
        return;
    }

    out[0] = '\0';
    if (value == NULL) {
        return;
    }

    (void) snprintf(out, out_cap, "%s", value);
}

static void cmaper_history_make_host_key(
    const cmaper_history_host_snapshot_t *host,
    char *out,
    size_t out_cap
) {
    char normalized_mac[CMAPER_HISTORY_MAC_CAP];

    if (out == NULL || out_cap == 0) {
        return;
    }
    out[0] = '\0';
    if (host == NULL) {
        return;
    }

    cmaper_history_normalize_mac(host->mac_address, normalized_mac, sizeof(normalized_mac));
    if (normalized_mac[0] != '\0') {
        (void) snprintf(out, out_cap, "mac:%s", normalized_mac);
        return;
    }

    if (host->primary_ip[0] != '\0') {
        (void) snprintf(out, out_cap, "ip:%s", host->primary_ip);
        return;
    }

    (void) snprintf(out, out_cap, "device:%s", host->device_id);
}

static bool cmaper_history_host_mac_equal(
    const cmaper_history_host_snapshot_t *left,
    const cmaper_history_host_snapshot_t *right
) {
    char left_mac[CMAPER_HISTORY_MAC_CAP];
    char right_mac[CMAPER_HISTORY_MAC_CAP];

    if (left == NULL || right == NULL) {
        return false;
    }

    cmaper_history_normalize_mac(left->mac_address, left_mac, sizeof(left_mac));
    cmaper_history_normalize_mac(right->mac_address, right_mac, sizeof(right_mac));
    if (left_mac[0] == '\0' || right_mac[0] == '\0') {
        return false;
    }

    return strcmp(left_mac, right_mac) == 0;
}

static bool cmaper_history_port_equal(
    const cmaper_history_port_signal_t *left,
    const cmaper_history_port_signal_t *right
) {
    if (left == NULL || right == NULL) {
        return false;
    }
    if (left->port != right->port) {
        return false;
    }
    return strcmp(left->protocol, right->protocol) == 0;
}

static bool cmaper_history_fingerprint_equal(
    const cmaper_history_fingerprint_signal_t *left,
    const cmaper_history_fingerprint_signal_t *right
) {
    if (left == NULL || right == NULL) {
        return false;
    }

    if (strcmp(left->kind, right->kind) != 0) {
        return false;
    }
    if (!cmaper_history_fuzzy_equal(left->value, right->value)) {
        return false;
    }
    if (left->has_service_context != right->has_service_context) {
        return false;
    }
    if (!left->has_service_context) {
        return true;
    }
    if (left->port != right->port) {
        return false;
    }
    return strcmp(left->protocol, right->protocol) == 0;
}

static bool cmaper_history_finding_identity_equal(
    const cmaper_history_finding_signal_t *left,
    const cmaper_history_finding_signal_t *right
) {
    if (left == NULL || right == NULL) {
        return false;
    }

    if (!cmaper_history_fuzzy_equal(left->key, right->key)) {
        return false;
    }
    if (left->has_service_context != right->has_service_context) {
        return false;
    }
    if (!left->has_service_context) {
        return true;
    }
    if (left->port != right->port) {
        return false;
    }
    return strcmp(left->protocol, right->protocol) == 0;
}

static bool cmaper_history_surface_equal(
    const cmaper_history_surface_signal_t *left,
    const cmaper_history_surface_signal_t *right
) {
    if (left == NULL || right == NULL) {
        return false;
    }
    if (!cmaper_history_fuzzy_equal(left->type, right->type)) {
        return false;
    }
    if (!cmaper_history_fuzzy_equal(left->detail, right->detail)) {
        return false;
    }
    if (left->has_service_context != right->has_service_context) {
        return false;
    }
    if (!left->has_service_context) {
        return true;
    }
    if (left->port != right->port) {
        return false;
    }
    return strcmp(left->protocol, right->protocol) == 0;
}

static bool cmaper_history_finding_is_open(const cmaper_history_finding_signal_t *finding) {
    if (finding == NULL) {
        return false;
    }
    return cmaper_history_fuzzy_equal(finding->state, "open");
}

static bool cmaper_history_finding_is_high_or_worse(const cmaper_history_finding_signal_t *finding) {
    if (finding == NULL) {
        return false;
    }
    return cmaper_history_fuzzy_equal(finding->severity, "high")
        || cmaper_history_fuzzy_equal(finding->severity, "critical");
}

static bool cmaper_history_surface_is_risky(const cmaper_history_surface_signal_t *surface) {
    static const char *RISKY_TYPES[] = {
        "ssh",
        "telnet",
        "rdp",
        "winrm-http",
        "winrm-https",
        "docker-api",
        "docker-api-tls",
        "smb",
        "vnc",
        "k8s-api"
    };
    size_t i;

    if (surface == NULL) {
        return false;
    }

    for (i = 0; i < sizeof(RISKY_TYPES) / sizeof(RISKY_TYPES[0]); ++i) {
        if (cmaper_history_fuzzy_equal(surface->type, RISKY_TYPES[i])) {
            return true;
        }
    }
    return false;
}

static size_t cmaper_history_count_open_high_findings(const cmaper_history_host_snapshot_t *host) {
    size_t i;
    size_t count = 0;

    if (host == NULL) {
        return 0;
    }

    for (i = 0; i < host->finding_count; ++i) {
        const cmaper_history_finding_signal_t *finding = &host->findings[i];
        if (cmaper_history_finding_is_open(finding) && cmaper_history_finding_is_high_or_worse(finding)) {
            count += 1U;
        }
    }
    return count;
}

static size_t cmaper_history_count_ports_added(
    const cmaper_history_host_snapshot_t *from_host,
    const cmaper_history_host_snapshot_t *to_host
) {
    size_t i;
    size_t count = 0;

    if (from_host == NULL || to_host == NULL) {
        return 0;
    }

    for (i = 0; i < to_host->port_count; ++i) {
        size_t j;
        bool found = false;
        for (j = 0; j < from_host->port_count; ++j) {
            if (cmaper_history_port_equal(&to_host->ports[i], &from_host->ports[j])) {
                found = true;
                break;
            }
        }
        if (!found) {
            count += 1U;
        }
    }
    return count;
}

static size_t cmaper_history_count_ports_removed(
    const cmaper_history_host_snapshot_t *from_host,
    const cmaper_history_host_snapshot_t *to_host
) {
    return cmaper_history_count_ports_added(to_host, from_host);
}

static size_t cmaper_history_count_fingerprints_added(
    const cmaper_history_host_snapshot_t *from_host,
    const cmaper_history_host_snapshot_t *to_host
) {
    size_t i;
    size_t count = 0;

    if (from_host == NULL || to_host == NULL) {
        return 0;
    }

    for (i = 0; i < to_host->fingerprint_count; ++i) {
        size_t j;
        bool found = false;
        for (j = 0; j < from_host->fingerprint_count; ++j) {
            if (cmaper_history_fingerprint_equal(&to_host->fingerprints[i], &from_host->fingerprints[j])) {
                found = true;
                break;
            }
        }
        if (!found) {
            count += 1U;
        }
    }
    return count;
}

static size_t cmaper_history_count_fingerprints_removed(
    const cmaper_history_host_snapshot_t *from_host,
    const cmaper_history_host_snapshot_t *to_host
) {
    return cmaper_history_count_fingerprints_added(to_host, from_host);
}

static void cmaper_history_count_finding_changes(
    const cmaper_history_host_snapshot_t *from_host,
    const cmaper_history_host_snapshot_t *to_host,
    size_t *out_opened,
    size_t *out_resolved,
    size_t *out_high_opened
) {
    size_t opened = 0;
    size_t resolved = 0;
    size_t high_opened = 0;
    size_t i;

    if (out_opened != NULL) {
        *out_opened = 0;
    }
    if (out_resolved != NULL) {
        *out_resolved = 0;
    }
    if (out_high_opened != NULL) {
        *out_high_opened = 0;
    }

    if (from_host == NULL || to_host == NULL) {
        return;
    }

    for (i = 0; i < from_host->finding_count; ++i) {
        const cmaper_history_finding_signal_t *from_finding = &from_host->findings[i];
        bool still_open = false;
        size_t j;

        if (!cmaper_history_finding_is_open(from_finding)) {
            continue;
        }

        for (j = 0; j < to_host->finding_count; ++j) {
            const cmaper_history_finding_signal_t *to_finding = &to_host->findings[j];
            if (!cmaper_history_finding_identity_equal(from_finding, to_finding)) {
                continue;
            }
            if (cmaper_history_finding_is_open(to_finding)) {
                still_open = true;
                break;
            }
        }

        if (!still_open) {
            resolved += 1U;
        }
    }

    for (i = 0; i < to_host->finding_count; ++i) {
        const cmaper_history_finding_signal_t *to_finding = &to_host->findings[i];
        bool was_open = false;
        size_t j;

        if (!cmaper_history_finding_is_open(to_finding)) {
            continue;
        }

        for (j = 0; j < from_host->finding_count; ++j) {
            const cmaper_history_finding_signal_t *from_finding = &from_host->findings[j];
            if (!cmaper_history_finding_identity_equal(from_finding, to_finding)) {
                continue;
            }
            if (cmaper_history_finding_is_open(from_finding)) {
                was_open = true;
                break;
            }
        }

        if (!was_open) {
            opened += 1U;
            if (cmaper_history_finding_is_high_or_worse(to_finding)) {
                high_opened += 1U;
            }
        }
    }

    if (out_opened != NULL) {
        *out_opened = opened;
    }
    if (out_resolved != NULL) {
        *out_resolved = resolved;
    }
    if (out_high_opened != NULL) {
        *out_high_opened = high_opened;
    }
}

static void cmaper_history_count_surface_changes(
    const cmaper_history_host_snapshot_t *from_host,
    const cmaper_history_host_snapshot_t *to_host,
    size_t *out_added,
    size_t *out_removed,
    size_t *out_risky_added
) {
    size_t added = 0;
    size_t removed = 0;
    size_t risky_added = 0;
    size_t i;

    if (out_added != NULL) {
        *out_added = 0;
    }
    if (out_removed != NULL) {
        *out_removed = 0;
    }
    if (out_risky_added != NULL) {
        *out_risky_added = 0;
    }

    if (from_host == NULL || to_host == NULL) {
        return;
    }

    for (i = 0; i < to_host->surface_count; ++i) {
        size_t j;
        bool found = false;
        for (j = 0; j < from_host->surface_count; ++j) {
            if (cmaper_history_surface_equal(&to_host->surfaces[i], &from_host->surfaces[j])) {
                found = true;
                break;
            }
        }
        if (!found) {
            added += 1U;
            if (cmaper_history_surface_is_risky(&to_host->surfaces[i])) {
                risky_added += 1U;
            }
        }
    }

    for (i = 0; i < from_host->surface_count; ++i) {
        size_t j;
        bool found = false;
        for (j = 0; j < to_host->surface_count; ++j) {
            if (cmaper_history_surface_equal(&from_host->surfaces[i], &to_host->surfaces[j])) {
                found = true;
                break;
            }
        }
        if (!found) {
            removed += 1U;
        }
    }

    if (out_added != NULL) {
        *out_added = added;
    }
    if (out_removed != NULL) {
        *out_removed = removed;
    }
    if (out_risky_added != NULL) {
        *out_risky_added = risky_added;
    }
}

static int cmaper_history_find_to_match_by_mac(
    const cmaper_history_host_snapshot_t *from_host,
    const cmaper_history_host_snapshot_t *to_hosts,
    const bool *to_matched,
    size_t to_count
) {
    int fallback = -1;
    size_t i;

    if (from_host == NULL || to_hosts == NULL || to_matched == NULL) {
        return -1;
    }

    for (i = 0; i < to_count; ++i) {
        if (to_matched[i]) {
            continue;
        }
        if (!cmaper_history_host_mac_equal(from_host, &to_hosts[i])) {
            continue;
        }
        if (cmaper_history_compare_ip(from_host->primary_ip, to_hosts[i].primary_ip) == 0) {
            return (int) i;
        }
        if (fallback < 0) {
            fallback = (int) i;
        }
    }
    return fallback;
}

static int cmaper_history_find_to_match_by_ip(
    const cmaper_history_host_snapshot_t *from_host,
    const cmaper_history_host_snapshot_t *to_hosts,
    const bool *to_matched,
    size_t to_count
) {
    size_t i;

    if (from_host == NULL || to_hosts == NULL || to_matched == NULL) {
        return -1;
    }

    for (i = 0; i < to_count; ++i) {
        if (to_matched[i]) {
            continue;
        }
        if (cmaper_history_compare_ip(from_host->primary_ip, to_hosts[i].primary_ip) == 0) {
            return (int) i;
        }
    }
    return -1;
}

static cmaper_err_t cmaper_history_append_changed_host(
    cmaper_history_diff_report_t *report,
    const cmaper_history_changed_host_t *row
) {
    cmaper_history_changed_host_t *next;

    if (report == NULL || row == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    next = (cmaper_history_changed_host_t *) realloc(
        report->changed_hosts,
        (report->changed_host_count + 1U) * sizeof(cmaper_history_changed_host_t)
    );
    if (next == NULL) {
        return CMAPER_ERR_OOM;
    }

    report->changed_hosts = next;
    report->changed_hosts[report->changed_host_count] = *row;
    report->changed_host_count += 1U;
    return CMAPER_OK;
}

const char *cmaper_history_host_reason_name(cmaper_history_host_reason_t reason) {
    switch (reason) {
    case CMAPER_HISTORY_HOST_REASON_ADDED:
        return "added";
    case CMAPER_HISTORY_HOST_REASON_REMOVED:
        return "removed";
    case CMAPER_HISTORY_HOST_REASON_MOVED:
        return "moved";
    case CMAPER_HISTORY_HOST_REASON_STATUS_CHANGED:
        return "status-changed";
    case CMAPER_HISTORY_HOST_REASON_HOSTNAME_CHANGED:
        return "hostname-changed";
    case CMAPER_HISTORY_HOST_REASON_MAC_CHANGED:
        return "mac-changed";
    case CMAPER_HISTORY_HOST_REASON_PORTS_CHANGED:
        return "ports-changed";
    case CMAPER_HISTORY_HOST_REASON_FINGERPRINTS_CHANGED:
        return "fingerprints-changed";
    case CMAPER_HISTORY_HOST_REASON_FINDINGS_CHANGED:
        return "findings-changed";
    case CMAPER_HISTORY_HOST_REASON_MANAGEMENT_CHANGED:
        return "management-changed";
    case CMAPER_HISTORY_HOST_REASON_NONE:
        break;
    }

    return "unknown";
}

bool cmaper_history_host_reason_has(unsigned int mask, cmaper_history_host_reason_t reason) {
    return (mask & (unsigned int) reason) != 0U;
}

cmaper_err_t cmaper_history_diff_build(
    const cmaper_history_host_snapshot_t *from_hosts,
    size_t from_host_count,
    const cmaper_history_host_snapshot_t *to_hosts,
    size_t to_host_count,
    cmaper_history_diff_report_t *out_report
) {
    bool *to_matched = NULL;
    size_t i;
    cmaper_err_t rc = CMAPER_OK;

    if (out_report == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    if (out_report->changed_hosts != NULL) {
        free(out_report->changed_hosts);
        out_report->changed_hosts = NULL;
    }
    out_report->changed_host_count = 0;
    cmaper_history_diff_summary_init(&out_report->summary);
    out_report->summary.hosts_from = from_host_count;
    out_report->summary.hosts_to = to_host_count;

    if (to_host_count > 0) {
        to_matched = (bool *) calloc(to_host_count, sizeof(bool));
        if (to_matched == NULL) {
            return CMAPER_ERR_OOM;
        }
    }

    for (i = 0; i < from_host_count; ++i) {
        const cmaper_history_host_snapshot_t *from_host = &from_hosts[i];
        int to_index = -1;
        bool matched_by_mac = false;

        to_index = cmaper_history_find_to_match_by_mac(from_host, to_hosts, to_matched, to_host_count);
        if (to_index >= 0) {
            matched_by_mac = true;
        } else {
            to_index = cmaper_history_find_to_match_by_ip(from_host, to_hosts, to_matched, to_host_count);
            matched_by_mac = false;
        }

        if (to_index < 0) {
            cmaper_history_changed_host_t row;
            cmaper_history_changed_host_init(&row);
            cmaper_history_make_host_key(from_host, row.host_key, sizeof(row.host_key));
            cmaper_history_copy_string(row.match_strategy, sizeof(row.match_strategy), "none");
            cmaper_history_copy_string(row.from_ip, sizeof(row.from_ip), from_host->primary_ip);
            cmaper_history_copy_string(row.from_status, sizeof(row.from_status), from_host->status);
            cmaper_history_copy_string(row.from_hostname, sizeof(row.from_hostname), from_host->hostname);
            cmaper_history_copy_string(row.mac_address, sizeof(row.mac_address), from_host->mac_address);
            row.reason_mask |= CMAPER_HISTORY_HOST_REASON_REMOVED;
            row.from_high_findings_open = cmaper_history_count_open_high_findings(from_host);

            rc = cmaper_history_append_changed_host(out_report, &row);
            if (rc != CMAPER_OK) {
                goto cleanup;
            }

            out_report->summary.hosts_removed += 1U;
            continue;
        }

        to_matched[to_index] = true;

        {
            const cmaper_history_host_snapshot_t *to_host = &to_hosts[to_index];
            cmaper_history_changed_host_t row;

            cmaper_history_changed_host_init(&row);
            cmaper_history_make_host_key(
                matched_by_mac ? to_host : from_host,
                row.host_key,
                sizeof(row.host_key)
            );
            cmaper_history_copy_string(
                row.match_strategy,
                sizeof(row.match_strategy),
                matched_by_mac ? "mac" : "ip"
            );
            cmaper_history_copy_string(row.from_ip, sizeof(row.from_ip), from_host->primary_ip);
            cmaper_history_copy_string(row.to_ip, sizeof(row.to_ip), to_host->primary_ip);
            cmaper_history_copy_string(row.from_status, sizeof(row.from_status), from_host->status);
            cmaper_history_copy_string(row.to_status, sizeof(row.to_status), to_host->status);
            cmaper_history_copy_string(row.from_hostname, sizeof(row.from_hostname), from_host->hostname);
            cmaper_history_copy_string(row.to_hostname, sizeof(row.to_hostname), to_host->hostname);
            cmaper_history_copy_string(row.mac_address, sizeof(row.mac_address), to_host->mac_address);
            row.from_high_findings_open = cmaper_history_count_open_high_findings(from_host);
            row.to_high_findings_open = cmaper_history_count_open_high_findings(to_host);

            if (cmaper_history_compare_ip(from_host->primary_ip, to_host->primary_ip) != 0) {
                row.reason_mask |= CMAPER_HISTORY_HOST_REASON_MOVED;
                out_report->summary.hosts_moved += 1U;
            }
            if (!cmaper_history_fuzzy_equal(from_host->status, to_host->status)) {
                row.reason_mask |= CMAPER_HISTORY_HOST_REASON_STATUS_CHANGED;
            }
            if (!cmaper_history_fuzzy_equal(from_host->hostname, to_host->hostname)) {
                row.reason_mask |= CMAPER_HISTORY_HOST_REASON_HOSTNAME_CHANGED;
            }
            if (!cmaper_history_host_mac_equal(from_host, to_host)
                && (cmaper_history_text_nonempty(from_host->mac_address)
                    || cmaper_history_text_nonempty(to_host->mac_address))) {
                row.reason_mask |= CMAPER_HISTORY_HOST_REASON_MAC_CHANGED;
            }

            row.ports_added = cmaper_history_count_ports_added(from_host, to_host);
            row.ports_removed = cmaper_history_count_ports_removed(from_host, to_host);
            if (row.ports_added > 0 || row.ports_removed > 0) {
                row.reason_mask |= CMAPER_HISTORY_HOST_REASON_PORTS_CHANGED;
            }

            row.fingerprints_added = cmaper_history_count_fingerprints_added(from_host, to_host);
            row.fingerprints_removed = cmaper_history_count_fingerprints_removed(from_host, to_host);
            if (row.fingerprints_added > 0 || row.fingerprints_removed > 0) {
                row.reason_mask |= CMAPER_HISTORY_HOST_REASON_FINGERPRINTS_CHANGED;
            }

            cmaper_history_count_finding_changes(
                from_host,
                to_host,
                &row.findings_opened,
                &row.findings_resolved,
                &row.findings_high_opened
            );
            if (row.findings_opened > 0 || row.findings_resolved > 0) {
                row.reason_mask |= CMAPER_HISTORY_HOST_REASON_FINDINGS_CHANGED;
            }

            cmaper_history_count_surface_changes(
                from_host,
                to_host,
                &row.management_added,
                &row.management_removed,
                &row.risky_surfaces_added
            );
            if (row.management_added > 0 || row.management_removed > 0) {
                row.reason_mask |= CMAPER_HISTORY_HOST_REASON_MANAGEMENT_CHANGED;
            }

            out_report->summary.ports_added += row.ports_added;
            out_report->summary.ports_removed += row.ports_removed;
            out_report->summary.fingerprints_added += row.fingerprints_added;
            out_report->summary.fingerprints_removed += row.fingerprints_removed;
            out_report->summary.findings_opened += row.findings_opened;
            out_report->summary.findings_resolved += row.findings_resolved;
            out_report->summary.findings_high_opened += row.findings_high_opened;
            out_report->summary.management_added += row.management_added;
            out_report->summary.management_removed += row.management_removed;

            if (row.reason_mask == CMAPER_HISTORY_HOST_REASON_NONE) {
                out_report->summary.hosts_unchanged += 1U;
            } else {
                out_report->summary.hosts_changed += 1U;
                rc = cmaper_history_append_changed_host(out_report, &row);
                if (rc != CMAPER_OK) {
                    goto cleanup;
                }
            }
        }
    }

    for (i = 0; i < to_host_count; ++i) {
        if (to_matched != NULL && to_matched[i]) {
            continue;
        }

        {
            const cmaper_history_host_snapshot_t *to_host = &to_hosts[i];
            cmaper_history_changed_host_t row;
            cmaper_history_changed_host_init(&row);
            cmaper_history_make_host_key(to_host, row.host_key, sizeof(row.host_key));
            cmaper_history_copy_string(row.match_strategy, sizeof(row.match_strategy), "none");
            cmaper_history_copy_string(row.to_ip, sizeof(row.to_ip), to_host->primary_ip);
            cmaper_history_copy_string(row.to_status, sizeof(row.to_status), to_host->status);
            cmaper_history_copy_string(row.to_hostname, sizeof(row.to_hostname), to_host->hostname);
            cmaper_history_copy_string(row.mac_address, sizeof(row.mac_address), to_host->mac_address);
            row.reason_mask |= CMAPER_HISTORY_HOST_REASON_ADDED;
            row.to_high_findings_open = cmaper_history_count_open_high_findings(to_host);

            rc = cmaper_history_append_changed_host(out_report, &row);
            if (rc != CMAPER_OK) {
                goto cleanup;
            }
            out_report->summary.hosts_added += 1U;
        }
    }

cleanup:
    if (to_matched != NULL) {
        free(to_matched);
    }
    return rc;
}
