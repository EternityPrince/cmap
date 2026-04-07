#include "cmaper/scan/nmap_xml_model.h"

#include <stdlib.h>

static void cmaper_nmap_xml_script_dispose(cmaper_nmap_xml_script_t *script) {
  if (script == NULL) {
    return;
  }

  if (script->id != NULL) {
    free(script->id);
    script->id = NULL;
  }
  if (script->output != NULL) {
    free(script->output);
    script->output = NULL;
  }
}

static void
cmaper_nmap_xml_address_dispose(cmaper_nmap_xml_address_t *address) {
  if (address == NULL) {
    return;
  }

  if (address->addr != NULL) {
    free(address->addr);
    address->addr = NULL;
  }
  if (address->addrtype != NULL) {
    free(address->addrtype);
    address->addrtype = NULL;
  }
  if (address->vendor != NULL) {
    free(address->vendor);
    address->vendor = NULL;
  }
}

static void
cmaper_nmap_xml_hostname_dispose(cmaper_nmap_xml_hostname_t *hostname) {
  if (hostname == NULL) {
    return;
  }

  if (hostname->name != NULL) {
    free(hostname->name);
    hostname->name = NULL;
  }
  if (hostname->type != NULL) {
    free(hostname->type);
    hostname->type = NULL;
  }
}

static void cmaper_nmap_xml_status_dispose(cmaper_nmap_xml_status_t *status) {
  if (status == NULL) {
    return;
  }

  if (status->state != NULL) {
    free(status->state);
    status->state = NULL;
  }
  if (status->reason != NULL) {
    free(status->reason);
    status->reason = NULL;
  }
}

static void cmaper_nmap_xml_port_dispose(cmaper_nmap_xml_port_t *port) {
  size_t i;

  if (port == NULL) {
    return;
  }

  if (port->protocol != NULL) {
    free(port->protocol);
    port->protocol = NULL;
  }
  if (port->state != NULL) {
    free(port->state);
    port->state = NULL;
  }
  if (port->reason != NULL) {
    free(port->reason);
    port->reason = NULL;
  }
  if (port->service_name != NULL) {
    free(port->service_name);
    port->service_name = NULL;
  }
  if (port->service_product != NULL) {
    free(port->service_product);
    port->service_product = NULL;
  }
  if (port->service_version != NULL) {
    free(port->service_version);
    port->service_version = NULL;
  }

  if (port->scripts != NULL) {
    for (i = 0; i < port->script_count; ++i) {
      cmaper_nmap_xml_script_dispose(&port->scripts[i]);
    }
    free(port->scripts);
    port->scripts = NULL;
  }
  port->script_count = 0;
}

static void
cmaper_nmap_xml_osmatch_dispose(cmaper_nmap_xml_osmatch_t *osmatch) {
  if (osmatch == NULL) {
    return;
  }

  if (osmatch->name != NULL) {
    free(osmatch->name);
    osmatch->name = NULL;
  }
}

static void
cmaper_nmap_xml_trace_hop_dispose(cmaper_nmap_xml_trace_hop_t *hop) {
  if (hop == NULL) {
    return;
  }

  if (hop->ipaddr != NULL) {
    free(hop->ipaddr);
    hop->ipaddr = NULL;
  }
  if (hop->rtt != NULL) {
    free(hop->rtt);
    hop->rtt = NULL;
  }
  if (hop->host != NULL) {
    free(hop->host);
    hop->host = NULL;
  }
}

static void cmaper_nmap_xml_host_dispose(cmaper_nmap_xml_host_t *host) {
  size_t i;

  if (host == NULL) {
    return;
  }

  cmaper_nmap_xml_status_dispose(&host->status);

  if (host->addresses != NULL) {
    for (i = 0; i < host->address_count; ++i) {
      cmaper_nmap_xml_address_dispose(&host->addresses[i]);
    }
    free(host->addresses);
    host->addresses = NULL;
  }
  host->address_count = 0;

  if (host->hostnames != NULL) {
    for (i = 0; i < host->hostname_count; ++i) {
      cmaper_nmap_xml_hostname_dispose(&host->hostnames[i]);
    }
    free(host->hostnames);
    host->hostnames = NULL;
  }
  host->hostname_count = 0;

  if (host->ports != NULL) {
    for (i = 0; i < host->port_count; ++i) {
      cmaper_nmap_xml_port_dispose(&host->ports[i]);
    }
    free(host->ports);
    host->ports = NULL;
  }
  host->port_count = 0;

  if (host->host_scripts != NULL) {
    for (i = 0; i < host->host_script_count; ++i) {
      cmaper_nmap_xml_script_dispose(&host->host_scripts[i]);
    }
    free(host->host_scripts);
    host->host_scripts = NULL;
  }
  host->host_script_count = 0;

  if (host->os_matches != NULL) {
    for (i = 0; i < host->os_match_count; ++i) {
      cmaper_nmap_xml_osmatch_dispose(&host->os_matches[i]);
    }
    free(host->os_matches);
    host->os_matches = NULL;
  }
  host->os_match_count = 0;

  if (host->trace_hops != NULL) {
    for (i = 0; i < host->trace_hop_count; ++i) {
      cmaper_nmap_xml_trace_hop_dispose(&host->trace_hops[i]);
    }
    free(host->trace_hops);
    host->trace_hops = NULL;
  }
  host->trace_hop_count = 0;
}

void cmaper_nmap_xml_document_init(cmaper_nmap_xml_document_t *document) {
  if (document == NULL) {
    return;
  }

  document->run.scanner = NULL;
  document->run.args = NULL;
  document->run.start = NULL;
  document->run.startstr = NULL;
  document->run.version = NULL;
  document->run.xmloutputversion = NULL;

  document->runstats.time = NULL;
  document->runstats.timestr = NULL;
  document->runstats.elapsed = NULL;
  document->runstats.summary = NULL;
  document->runstats.exit_status = NULL;
  document->runstats.hosts_up = -1;
  document->runstats.hosts_down = -1;
  document->runstats.hosts_total = -1;

  document->hosts = NULL;
  document->host_count = 0;
}

void cmaper_nmap_xml_document_dispose(cmaper_nmap_xml_document_t *document) {
  size_t i;

  if (document == NULL) {
    return;
  }

  if (document->run.scanner != NULL) {
    free(document->run.scanner);
    document->run.scanner = NULL;
  }
  if (document->run.args != NULL) {
    free(document->run.args);
    document->run.args = NULL;
  }
  if (document->run.start != NULL) {
    free(document->run.start);
    document->run.start = NULL;
  }
  if (document->run.startstr != NULL) {
    free(document->run.startstr);
    document->run.startstr = NULL;
  }
  if (document->run.version != NULL) {
    free(document->run.version);
    document->run.version = NULL;
  }
  if (document->run.xmloutputversion != NULL) {
    free(document->run.xmloutputversion);
    document->run.xmloutputversion = NULL;
  }

  if (document->runstats.time != NULL) {
    free(document->runstats.time);
    document->runstats.time = NULL;
  }
  if (document->runstats.timestr != NULL) {
    free(document->runstats.timestr);
    document->runstats.timestr = NULL;
  }
  if (document->runstats.elapsed != NULL) {
    free(document->runstats.elapsed);
    document->runstats.elapsed = NULL;
  }
  if (document->runstats.summary != NULL) {
    free(document->runstats.summary);
    document->runstats.summary = NULL;
  }
  if (document->runstats.exit_status != NULL) {
    free(document->runstats.exit_status);
    document->runstats.exit_status = NULL;
  }
  document->runstats.hosts_up = -1;
  document->runstats.hosts_down = -1;
  document->runstats.hosts_total = -1;

  if (document->hosts != NULL) {
    for (i = 0; i < document->host_count; ++i) {
      cmaper_nmap_xml_host_dispose(&document->hosts[i]);
    }
    free(document->hosts);
    document->hosts = NULL;
  }
  document->host_count = 0;
}
