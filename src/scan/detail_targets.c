#include "cmaper/scan/detail_targets.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmaper/scan/nmap_xml_utils.h"

static void cmaper_scan_detail_target_diag_setf(
    cmaper_scan_detail_target_diag_t *diag,
    const char *field,
    const char *fmt,
    ...
) {
    va_list args;

    cmaper_scan_detail_target_diag_clear(diag);
    if (diag == NULL) {
        return;
    }

    diag->field = field;
    if (fmt == NULL) {
        return;
    }

    va_start(args, fmt);
    vsnprintf(diag->message, sizeof(diag->message), fmt, args);
    va_end(args);
}

static void cmaper_scan_detail_target_dispose(cmaper_scan_detail_target_t *target) {
    if (target == NULL) {
        return;
    }

    if (target->open_tcp_ports != NULL) {
        free(target->open_tcp_ports);
        target->open_tcp_ports = NULL;
    }
    target->open_tcp_port_count = 0;
    target->has_open_tcp_ports = false;
    target->ip[0] = '\0';
}

void cmaper_scan_detail_target_diag_clear(cmaper_scan_detail_target_diag_t *diag) {
    if (diag == NULL) {
        return;
    }

    diag->field = NULL;
    diag->message[0] = '\0';
}

void cmaper_scan_detail_targets_init(cmaper_scan_detail_target_list_t *list) {
    if (list == NULL) {
        return;
    }

    list->items = NULL;
    list->count = 0;
}

void cmaper_scan_detail_targets_dispose(cmaper_scan_detail_target_list_t *list) {
    size_t i;

    if (list == NULL) {
        return;
    }

    if (list->items != NULL) {
        for (i = 0; i < list->count; ++i) {
            cmaper_scan_detail_target_dispose(&list->items[i]);
        }
        free(list->items);
        list->items = NULL;
    }
    list->count = 0;
}

static int cmaper_scan_detail_target_compare(const void *left, const void *right) {
    const cmaper_scan_detail_target_t *a = (const cmaper_scan_detail_target_t *) left;
    const cmaper_scan_detail_target_t *b = (const cmaper_scan_detail_target_t *) right;

    return cmaper_nmap_ip_compare(a->ip, b->ip);
}

static cmaper_err_t cmaper_scan_detail_target_union_ports(
    cmaper_scan_detail_target_t *target,
    const cmaper_scan_detail_target_t *other
) {
    size_t i = 0;
    size_t j = 0;
    size_t k = 0;
    int *merged;
    size_t merged_cap;

    if (target == NULL || other == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    if (other->open_tcp_port_count == 0 || other->open_tcp_ports == NULL) {
        return CMAPER_OK;
    }

    if (target->open_tcp_port_count == 0 || target->open_tcp_ports == NULL) {
        int *copy = (int *) malloc(other->open_tcp_port_count * sizeof(int));
        if (copy == NULL) {
            return CMAPER_ERR_OOM;
        }
        memcpy(copy, other->open_tcp_ports, other->open_tcp_port_count * sizeof(int));
        target->open_tcp_ports = copy;
        target->open_tcp_port_count = other->open_tcp_port_count;
        target->has_open_tcp_ports = true;
        return CMAPER_OK;
    }

    merged_cap = target->open_tcp_port_count + other->open_tcp_port_count;
    merged = (int *) malloc(merged_cap * sizeof(int));
    if (merged == NULL) {
        return CMAPER_ERR_OOM;
    }

    while (i < target->open_tcp_port_count && j < other->open_tcp_port_count) {
        int left_port = target->open_tcp_ports[i];
        int right_port = other->open_tcp_ports[j];
        int value;

        if (left_port < right_port) {
            value = left_port;
            i += 1U;
        } else if (left_port > right_port) {
            value = right_port;
            j += 1U;
        } else {
            value = left_port;
            i += 1U;
            j += 1U;
        }

        if (k == 0 || merged[k - 1U] != value) {
            merged[k++] = value;
        }
    }

    while (i < target->open_tcp_port_count) {
        int value = target->open_tcp_ports[i++];
        if (k == 0 || merged[k - 1U] != value) {
            merged[k++] = value;
        }
    }

    while (j < other->open_tcp_port_count) {
        int value = other->open_tcp_ports[j++];
        if (k == 0 || merged[k - 1U] != value) {
            merged[k++] = value;
        }
    }

    free(target->open_tcp_ports);
    target->open_tcp_ports = merged;
    target->open_tcp_port_count = k;
    target->has_open_tcp_ports = (k > 0);

    return CMAPER_OK;
}

static cmaper_err_t cmaper_scan_detail_target_list_append(
    cmaper_scan_detail_target_list_t *targets,
    cmaper_scan_detail_target_t target
) {
    cmaper_scan_detail_target_t *next;

    next = (cmaper_scan_detail_target_t *) realloc(
        targets->items,
        (targets->count + 1U) * sizeof(cmaper_scan_detail_target_t)
    );
    if (next == NULL) {
        return CMAPER_ERR_OOM;
    }

    targets->items = next;
    targets->items[targets->count] = target;
    targets->count += 1U;
    return CMAPER_OK;
}

static cmaper_err_t cmaper_scan_detail_targets_deduplicate(cmaper_scan_detail_target_list_t *targets) {
    size_t write_index = 0;
    size_t read_index;

    if (targets == NULL || targets->count == 0 || targets->items == NULL) {
        return CMAPER_OK;
    }

    for (read_index = 0; read_index < targets->count; ++read_index) {
        if (write_index == 0) {
            targets->items[write_index++] = targets->items[read_index];
            continue;
        }

        if (strcmp(targets->items[write_index - 1U].ip, targets->items[read_index].ip) != 0) {
            targets->items[write_index++] = targets->items[read_index];
            continue;
        }

        {
            cmaper_err_t rc = cmaper_scan_detail_target_union_ports(
                &targets->items[write_index - 1U],
                &targets->items[read_index]
            );
            if (rc != CMAPER_OK) {
                return rc;
            }
        }

        if (targets->items[read_index].open_tcp_ports != NULL) {
            free(targets->items[read_index].open_tcp_ports);
        }
        targets->items[read_index].open_tcp_ports = NULL;
        targets->items[read_index].open_tcp_port_count = 0;
    }

    targets->count = write_index;
    return CMAPER_OK;
}

cmaper_err_t cmaper_scan_detail_targets_build(
    const cmaper_nmap_xml_document_t *discovery_document,
    cmaper_scan_detail_target_list_t *targets,
    cmaper_scan_detail_target_diag_t *diag
) {
    size_t i;
    cmaper_err_t rc;

    if (discovery_document == NULL || targets == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    cmaper_scan_detail_target_diag_clear(diag);
    cmaper_scan_detail_targets_dispose(targets);
    cmaper_scan_detail_targets_init(targets);

    for (i = 0; i < discovery_document->host_count; ++i) {
        const cmaper_nmap_xml_host_t *host = &discovery_document->hosts[i];
        const char *ip;
        cmaper_scan_detail_target_t target;

        if (host->status.state == NULL || strcmp(host->status.state, "up") != 0) {
            continue;
        }

        ip = cmaper_nmap_host_primary_ip(host);
        if (ip == NULL || ip[0] == '\0') {
            continue;
        }

        memset(&target, 0, sizeof(target));
        if (snprintf(target.ip, sizeof(target.ip), "%s", ip) >= (int) sizeof(target.ip)) {
            cmaper_scan_detail_target_diag_setf(
                diag,
                "ip",
                "host primary ip exceeds internal limit: '%s'",
                ip
            );
            cmaper_scan_detail_target_dispose(&target);
            cmaper_scan_detail_targets_dispose(targets);
            return CMAPER_ERR_PARSE;
        }

        rc = cmaper_nmap_host_open_tcp_ports_sorted(
            host,
            &target.open_tcp_ports,
            &target.open_tcp_port_count
        );
        if (rc != CMAPER_OK) {
            cmaper_scan_detail_target_diag_setf(
                diag,
                "ports",
                "failed to extract open tcp ports for host '%s'",
                target.ip
            );
            cmaper_scan_detail_target_dispose(&target);
            cmaper_scan_detail_targets_dispose(targets);
            return rc;
        }
        target.has_open_tcp_ports = target.open_tcp_port_count > 0;

        rc = cmaper_scan_detail_target_list_append(targets, target);
        if (rc != CMAPER_OK) {
            cmaper_scan_detail_target_diag_setf(diag, "targets", "failed to append detail target");
            cmaper_scan_detail_target_dispose(&target);
            cmaper_scan_detail_targets_dispose(targets);
            return rc;
        }
    }

    if (targets->count > 1U) {
        qsort(
            targets->items,
            targets->count,
            sizeof(cmaper_scan_detail_target_t),
            cmaper_scan_detail_target_compare
        );

        rc = cmaper_scan_detail_targets_deduplicate(targets);
        if (rc != CMAPER_OK) {
            cmaper_scan_detail_target_diag_setf(diag, "targets", "failed to deduplicate detail targets");
            cmaper_scan_detail_targets_dispose(targets);
            return rc;
        }
    }

    return CMAPER_OK;
}
