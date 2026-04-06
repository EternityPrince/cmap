#include "cmaper/snapshot/internal/host_view_internal.h"

#include <string.h>

#include "cmaper/scan/nmap_xml_utils.h"

static const char *cmaper_snapshot_first_hostname(const cmaper_nmap_xml_host_t *host) {
    size_t i;

    if (host == NULL) {
        return NULL;
    }

    for (i = 0; i < host->hostname_count; ++i) {
        if (host->hostnames[i].name != NULL && host->hostnames[i].name[0] != '\0') {
            return host->hostnames[i].name;
        }
    }

    return NULL;
}

static const char *cmaper_snapshot_host_address_type_for_ip(
    const cmaper_nmap_xml_host_t *host,
    const char *ip
) {
    size_t i;

    if (host == NULL || ip == NULL || ip[0] == '\0') {
        return NULL;
    }

    for (i = 0; i < host->address_count; ++i) {
        const cmaper_nmap_xml_address_t *address = &host->addresses[i];
        if (address->addr == NULL || address->addrtype == NULL) {
            continue;
        }
        if (strcmp(address->addr, ip) == 0) {
            return address->addrtype;
        }
    }

    return NULL;
}

static const cmaper_nmap_xml_host_t *cmaper_snapshot_pick_primary_host(
    const cmaper_snapshot_merged_host_t *merged
) {
    if (merged == NULL) {
        return NULL;
    }

    if (merged->detail_doc != NULL && merged->detail_doc->host != NULL) {
        return merged->detail_doc->host;
    }

    return merged->discovery_host;
}

static const cmaper_nmap_xml_host_t *cmaper_snapshot_pick_secondary_host(
    const cmaper_snapshot_merged_host_t *merged
) {
    if (merged == NULL) {
        return NULL;
    }

    if (merged->detail_doc != NULL && merged->detail_doc->host != NULL) {
        return merged->discovery_host;
    }

    return NULL;
}

static const char *cmaper_snapshot_pick_status(
    const cmaper_nmap_xml_host_t *primary,
    const cmaper_nmap_xml_host_t *secondary
) {
    if (primary != NULL && primary->status.state != NULL && primary->status.state[0] != '\0') {
        return primary->status.state;
    }
    if (secondary != NULL && secondary->status.state != NULL && secondary->status.state[0] != '\0') {
        return secondary->status.state;
    }
    return NULL;
}

static const char *cmaper_snapshot_pick_hostname(
    const cmaper_nmap_xml_host_t *primary,
    const cmaper_nmap_xml_host_t *secondary
) {
    const char *value = cmaper_snapshot_first_hostname(primary);
    if (value != NULL) {
        return value;
    }

    return cmaper_snapshot_first_hostname(secondary);
}

static const cmaper_nmap_xml_address_t *cmaper_snapshot_pick_mac(
    const cmaper_nmap_xml_host_t *primary,
    const cmaper_nmap_xml_host_t *secondary
) {
    const cmaper_nmap_xml_address_t *address = cmaper_nmap_host_mac_address(primary);
    if (address != NULL && address->addr != NULL && address->addr[0] != '\0') {
        return address;
    }

    return cmaper_nmap_host_mac_address(secondary);
}

static void cmaper_snapshot_pick_port_view(
    const cmaper_nmap_xml_host_t *primary,
    const cmaper_nmap_xml_host_t *secondary,
    const cmaper_nmap_xml_port_t **out_ports,
    size_t *out_count
) {
    if (out_ports != NULL) {
        *out_ports = NULL;
    }
    if (out_count != NULL) {
        *out_count = 0;
    }

    if (primary != NULL && primary->port_count > 0) {
        if (out_ports != NULL) {
            *out_ports = primary->ports;
        }
        if (out_count != NULL) {
            *out_count = primary->port_count;
        }
        return;
    }

    if (secondary != NULL && secondary->port_count > 0) {
        if (out_ports != NULL) {
            *out_ports = secondary->ports;
        }
        if (out_count != NULL) {
            *out_count = secondary->port_count;
        }
    }
}

static void cmaper_snapshot_pick_script_view(
    const cmaper_nmap_xml_host_t *primary,
    const cmaper_nmap_xml_host_t *secondary,
    const cmaper_nmap_xml_script_t **out_scripts,
    size_t *out_count
) {
    if (out_scripts != NULL) {
        *out_scripts = NULL;
    }
    if (out_count != NULL) {
        *out_count = 0;
    }

    if (primary != NULL && primary->host_script_count > 0) {
        if (out_scripts != NULL) {
            *out_scripts = primary->host_scripts;
        }
        if (out_count != NULL) {
            *out_count = primary->host_script_count;
        }
        return;
    }

    if (secondary != NULL && secondary->host_script_count > 0) {
        if (out_scripts != NULL) {
            *out_scripts = secondary->host_scripts;
        }
        if (out_count != NULL) {
            *out_count = secondary->host_script_count;
        }
    }
}

static void cmaper_snapshot_pick_os_view(
    const cmaper_nmap_xml_host_t *primary,
    const cmaper_nmap_xml_host_t *secondary,
    const cmaper_nmap_xml_osmatch_t **out_os,
    size_t *out_count
) {
    if (out_os != NULL) {
        *out_os = NULL;
    }
    if (out_count != NULL) {
        *out_count = 0;
    }

    if (primary != NULL && primary->os_match_count > 0) {
        if (out_os != NULL) {
            *out_os = primary->os_matches;
        }
        if (out_count != NULL) {
            *out_count = primary->os_match_count;
        }
        return;
    }

    if (secondary != NULL && secondary->os_match_count > 0) {
        if (out_os != NULL) {
            *out_os = secondary->os_matches;
        }
        if (out_count != NULL) {
            *out_count = secondary->os_match_count;
        }
    }
}

static void cmaper_snapshot_pick_trace_view(
    const cmaper_nmap_xml_host_t *primary,
    const cmaper_nmap_xml_host_t *secondary,
    const cmaper_nmap_xml_trace_hop_t **out_hops,
    size_t *out_count
) {
    if (out_hops != NULL) {
        *out_hops = NULL;
    }
    if (out_count != NULL) {
        *out_count = 0;
    }

    if (primary != NULL && primary->trace_hop_count > 0) {
        if (out_hops != NULL) {
            *out_hops = primary->trace_hops;
        }
        if (out_count != NULL) {
            *out_count = primary->trace_hop_count;
        }
        return;
    }

    if (secondary != NULL && secondary->trace_hop_count > 0) {
        if (out_hops != NULL) {
            *out_hops = secondary->trace_hops;
        }
        if (out_count != NULL) {
            *out_count = secondary->trace_hop_count;
        }
    }
}

static const char *cmaper_snapshot_observation_source(const cmaper_snapshot_merged_host_t *merged) {
    if (merged == NULL) {
        return "merged";
    }

    if (merged->detail_doc != NULL && merged->detail_doc->host != NULL
        && merged->discovery_host != NULL) {
        return "merged";
    }
    if (merged->detail_doc != NULL && merged->detail_doc->host != NULL) {
        return "detail";
    }

    return "discovery";
}

cmaper_err_t cmaper_snapshot_build_host_view(
    const cmaper_snapshot_merged_host_t *merged,
    cmaper_snapshot_host_view_t *out_view
) {
    const cmaper_nmap_xml_host_t *primary;
    const cmaper_nmap_xml_host_t *secondary;
    const char *ip;

    if (merged == NULL || out_view == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    memset(out_view, 0, sizeof(*out_view));

    primary = cmaper_snapshot_pick_primary_host(merged);
    secondary = cmaper_snapshot_pick_secondary_host(merged);

    ip = merged->ip[0] != '\0' ? merged->ip : cmaper_nmap_host_primary_ip(primary);
    if (ip == NULL || ip[0] == '\0') {
        return CMAPER_ERR_PARSE;
    }

    out_view->primary = primary;
    out_view->secondary = secondary;
    out_view->ip = ip;

    out_view->ip_type = cmaper_snapshot_host_address_type_for_ip(primary, ip);
    if (out_view->ip_type == NULL) {
        out_view->ip_type = cmaper_snapshot_host_address_type_for_ip(secondary, ip);
    }

    out_view->status = cmaper_snapshot_pick_status(primary, secondary);
    out_view->hostname = cmaper_snapshot_pick_hostname(primary, secondary);
    out_view->mac = cmaper_snapshot_pick_mac(primary, secondary);
    out_view->observation_source = cmaper_snapshot_observation_source(merged);
    out_view->detail_xml_path = merged->detail_doc != NULL ? merged->detail_doc->xml_path : NULL;

    cmaper_snapshot_pick_port_view(primary, secondary, &out_view->ports, &out_view->port_count);
    cmaper_snapshot_pick_script_view(
        primary,
        secondary,
        &out_view->host_scripts,
        &out_view->host_script_count
    );
    cmaper_snapshot_pick_os_view(primary, secondary, &out_view->os_matches, &out_view->os_count);
    cmaper_snapshot_pick_trace_view(primary, secondary, &out_view->trace_hops, &out_view->trace_count);

    return CMAPER_OK;
}
