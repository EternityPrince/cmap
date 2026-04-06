#include "cmaper/scan/internal/detail_target_internal.h"

#include <stdlib.h>
#include <string.h>

#include "cmaper/scan/nmap_xml_parse.h"
#include "cmaper/scan/nmap_xml_utils.h"

cmaper_err_t cmaper_scan_detail_target_extract_probe_ports(
    const char *probe_xml,
    size_t probe_xml_size,
    const char *target_ip,
    int **out_ports,
    size_t *out_port_count
) {
    cmaper_nmap_xml_document_t document;
    cmaper_nmap_xml_diag_t diag;
    cmaper_err_t rc;
    size_t i;
    const cmaper_nmap_xml_host_t *fallback_up_host = NULL;

    if (probe_xml == NULL || target_ip == NULL || out_ports == NULL || out_port_count == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    *out_ports = NULL;
    *out_port_count = 0;

    cmaper_nmap_xml_document_init(&document);
    cmaper_nmap_xml_diag_clear(&diag);

    rc = cmaper_nmap_xml_parse_memory(probe_xml, probe_xml_size, &document, &diag);
    if (rc != CMAPER_OK) {
        cmaper_nmap_xml_document_dispose(&document);
        return rc;
    }

    for (i = 0; i < document.host_count; ++i) {
        const cmaper_nmap_xml_host_t *host = &document.hosts[i];
        const char *ip = cmaper_nmap_host_primary_ip(host);

        if (host->status.state != NULL && strcmp(host->status.state, "up") == 0 && fallback_up_host == NULL) {
            fallback_up_host = host;
        }

        if (ip != NULL && strcmp(ip, target_ip) == 0) {
            rc = cmaper_nmap_host_open_tcp_ports_sorted(host, out_ports, out_port_count);
            cmaper_nmap_xml_document_dispose(&document);
            return rc;
        }
    }

    if (fallback_up_host != NULL) {
        rc = cmaper_nmap_host_open_tcp_ports_sorted(fallback_up_host, out_ports, out_port_count);
        cmaper_nmap_xml_document_dispose(&document);
        return rc;
    }

    cmaper_nmap_xml_document_dispose(&document);
    return CMAPER_OK;
}

bool cmaper_scan_detail_target_count_scripts(
    const char *xml_data,
    size_t xml_size,
    const char *target_ip,
    size_t *out_scripts_count
) {
    cmaper_nmap_xml_document_t document;
    cmaper_nmap_xml_diag_t diag;
    const cmaper_nmap_xml_host_t *selected = NULL;
    const cmaper_nmap_xml_host_t *fallback_up = NULL;
    size_t i;
    size_t scripts_count = 0;
    cmaper_err_t rc;

    if (xml_data == NULL || xml_size == 0 || target_ip == NULL || out_scripts_count == NULL) {
        return false;
    }

    *out_scripts_count = 0;
    cmaper_nmap_xml_document_init(&document);
    cmaper_nmap_xml_diag_clear(&diag);

    rc = cmaper_nmap_xml_parse_memory(xml_data, xml_size, &document, &diag);
    if (rc != CMAPER_OK) {
        cmaper_nmap_xml_document_dispose(&document);
        return false;
    }

    for (i = 0; i < document.host_count; ++i) {
        const cmaper_nmap_xml_host_t *host = &document.hosts[i];
        const char *ip = cmaper_nmap_host_primary_ip(host);

        if (host->status.state != NULL && strcmp(host->status.state, "up") == 0 && fallback_up == NULL) {
            fallback_up = host;
        }

        if (ip != NULL && strcmp(ip, target_ip) == 0) {
            selected = host;
            break;
        }
    }

    if (selected == NULL) {
        selected = fallback_up;
    }

    if (selected != NULL) {
        scripts_count += selected->host_script_count;
        for (i = 0; i < selected->port_count; ++i) {
            scripts_count += selected->ports[i].script_count;
        }
        *out_scripts_count = scripts_count;
        cmaper_nmap_xml_document_dispose(&document);
        return true;
    }

    cmaper_nmap_xml_document_dispose(&document);
    return false;
}
