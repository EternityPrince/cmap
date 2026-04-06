#ifndef CMAPER_SCAN_NMAP_XML_MODEL_H
#define CMAPER_SCAN_NMAP_XML_MODEL_H

#include <stddef.h>

typedef struct {
    char *id;
    char *output;
} cmaper_nmap_xml_script_t;

typedef struct {
    char *addr;
    char *addrtype;
    char *vendor;
} cmaper_nmap_xml_address_t;

typedef struct {
    char *name;
    char *type;
} cmaper_nmap_xml_hostname_t;

typedef struct {
    char *state;
    char *reason;
} cmaper_nmap_xml_status_t;

typedef struct {
    char *protocol;
    int portid;
    char *state;
    char *reason;
    char *service_name;
    char *service_product;
    char *service_version;
    cmaper_nmap_xml_script_t *scripts;
    size_t script_count;
} cmaper_nmap_xml_port_t;

typedef struct {
    char *name;
    int accuracy;
    int line;
} cmaper_nmap_xml_osmatch_t;

typedef struct {
    int ttl;
    char *ipaddr;
    char *rtt;
    char *host;
} cmaper_nmap_xml_trace_hop_t;

typedef struct {
    cmaper_nmap_xml_status_t status;
    cmaper_nmap_xml_address_t *addresses;
    size_t address_count;
    cmaper_nmap_xml_hostname_t *hostnames;
    size_t hostname_count;
    cmaper_nmap_xml_port_t *ports;
    size_t port_count;
    cmaper_nmap_xml_script_t *host_scripts;
    size_t host_script_count;
    cmaper_nmap_xml_osmatch_t *os_matches;
    size_t os_match_count;
    cmaper_nmap_xml_trace_hop_t *trace_hops;
    size_t trace_hop_count;
} cmaper_nmap_xml_host_t;

typedef struct {
    char *scanner;
    char *args;
    char *start;
    char *startstr;
    char *version;
    char *xmloutputversion;
} cmaper_nmap_xml_run_meta_t;

typedef struct {
    char *time;
    char *timestr;
    char *elapsed;
    char *summary;
    char *exit_status;
    int hosts_up;
    int hosts_down;
    int hosts_total;
} cmaper_nmap_xml_runstats_t;

typedef struct {
    cmaper_nmap_xml_run_meta_t run;
    cmaper_nmap_xml_runstats_t runstats;
    cmaper_nmap_xml_host_t *hosts;
    size_t host_count;
} cmaper_nmap_xml_document_t;

void cmaper_nmap_xml_document_init(cmaper_nmap_xml_document_t *document);
void cmaper_nmap_xml_document_dispose(cmaper_nmap_xml_document_t *document);

#endif
