#ifndef CMAPER_SCAN_NMAP_XML_UTILS_H
#define CMAPER_SCAN_NMAP_XML_UTILS_H

#include <stddef.h>

#include "cmaper/core/error.h"
#include "cmaper/scan/nmap_xml_model.h"

const char *cmaper_nmap_host_primary_ip(const cmaper_nmap_xml_host_t *host);
const cmaper_nmap_xml_address_t *cmaper_nmap_host_mac_address(const cmaper_nmap_xml_host_t *host);

cmaper_err_t cmaper_nmap_host_open_tcp_ports_sorted(
    const cmaper_nmap_xml_host_t *host,
    int **out_ports,
    size_t *out_count
);

int cmaper_nmap_ip_compare(const char *left, const char *right);

#endif
