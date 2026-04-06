#ifndef CMAPER_SCAN_INTERNAL_NMAP_XML_PARSE_INTERNAL_H
#define CMAPER_SCAN_INTERNAL_NMAP_XML_PARSE_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>

#include <libxml/tree.h>

#include "cmaper/scan/nmap_xml_parse.h"

bool cmaper_nmap_xml_node_is(const xmlNode *node, const char *name);
char *cmaper_nmap_xml_attr_dup(const xmlNode *node, const char *name);
int cmaper_nmap_xml_attr_int(const xmlNode *node, const char *name, int default_value);

void cmaper_nmap_xml_script_dispose(cmaper_nmap_xml_script_t *script);
void cmaper_nmap_xml_address_dispose(cmaper_nmap_xml_address_t *address);
void cmaper_nmap_xml_hostname_dispose(cmaper_nmap_xml_hostname_t *hostname);
void cmaper_nmap_xml_port_dispose(cmaper_nmap_xml_port_t *port);
void cmaper_nmap_xml_osmatch_dispose(cmaper_nmap_xml_osmatch_t *osmatch);
void cmaper_nmap_xml_trace_hop_dispose(cmaper_nmap_xml_trace_hop_t *hop);
void cmaper_nmap_xml_host_dispose(cmaper_nmap_xml_host_t *host);

cmaper_err_t cmaper_nmap_xml_append_script(
    cmaper_nmap_xml_script_t **items,
    size_t *count,
    cmaper_nmap_xml_script_t script
);

cmaper_err_t cmaper_nmap_xml_append_address(
    cmaper_nmap_xml_address_t **items,
    size_t *count,
    cmaper_nmap_xml_address_t address
);

cmaper_err_t cmaper_nmap_xml_append_hostname(
    cmaper_nmap_xml_hostname_t **items,
    size_t *count,
    cmaper_nmap_xml_hostname_t hostname
);

cmaper_err_t cmaper_nmap_xml_append_port(
    cmaper_nmap_xml_port_t **items,
    size_t *count,
    cmaper_nmap_xml_port_t port
);

cmaper_err_t cmaper_nmap_xml_append_osmatch(
    cmaper_nmap_xml_osmatch_t **items,
    size_t *count,
    cmaper_nmap_xml_osmatch_t osmatch
);

cmaper_err_t cmaper_nmap_xml_append_trace_hop(
    cmaper_nmap_xml_trace_hop_t **items,
    size_t *count,
    cmaper_nmap_xml_trace_hop_t hop
);

cmaper_err_t cmaper_nmap_xml_append_host(
    cmaper_nmap_xml_document_t *document,
    cmaper_nmap_xml_host_t host
);

cmaper_err_t cmaper_nmap_xml_parse_script_node(
    const xmlNode *script_node,
    cmaper_nmap_xml_script_t *script
);

#endif
