#include "cmaper/scan/nmap_xml_utils.h"

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static int cmaper_nmap_int_compare(const void *left, const void *right) {
    int a = *((const int *) left);
    int b = *((const int *) right);

    if (a < b) {
        return -1;
    }
    if (a > b) {
        return 1;
    }
    return 0;
}

static int cmaper_nmap_ip_family(const char *ip) {
    struct in_addr v4;
    struct in6_addr v6;

    if (ip == NULL || ip[0] == '\0') {
        return 0;
    }

    if (inet_pton(AF_INET, ip, &v4) == 1) {
        return AF_INET;
    }
    if (inet_pton(AF_INET6, ip, &v6) == 1) {
        return AF_INET6;
    }
    return 0;
}

const char *cmaper_nmap_host_primary_ip(const cmaper_nmap_xml_host_t *host) {
    size_t i;

    if (host == NULL) {
        return NULL;
    }

    for (i = 0; i < host->address_count; ++i) {
        const cmaper_nmap_xml_address_t *address = &host->addresses[i];
        if (address->addr == NULL || address->addrtype == NULL) {
            continue;
        }
        if (strcmp(address->addrtype, "ipv4") == 0) {
            return address->addr;
        }
    }

    for (i = 0; i < host->address_count; ++i) {
        const cmaper_nmap_xml_address_t *address = &host->addresses[i];
        if (address->addr == NULL || address->addrtype == NULL) {
            continue;
        }
        if (strcmp(address->addrtype, "ipv6") == 0) {
            return address->addr;
        }
    }

    for (i = 0; i < host->address_count; ++i) {
        if (host->addresses[i].addr != NULL && host->addresses[i].addr[0] != '\0') {
            return host->addresses[i].addr;
        }
    }

    return NULL;
}

const cmaper_nmap_xml_address_t *cmaper_nmap_host_mac_address(const cmaper_nmap_xml_host_t *host) {
    size_t i;

    if (host == NULL) {
        return NULL;
    }

    for (i = 0; i < host->address_count; ++i) {
        const cmaper_nmap_xml_address_t *address = &host->addresses[i];
        if (address->addr == NULL || address->addrtype == NULL) {
            continue;
        }
        if (strcmp(address->addrtype, "mac") == 0) {
            return address;
        }
    }

    return NULL;
}

cmaper_err_t cmaper_nmap_host_open_tcp_ports_sorted(
    const cmaper_nmap_xml_host_t *host,
    int **out_ports,
    size_t *out_count
) {
    int *ports = NULL;
    size_t count = 0;
    size_t capacity = 0;
    size_t i;
    size_t unique_count;

    if (out_ports == NULL || out_count == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    *out_ports = NULL;
    *out_count = 0;

    if (host == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    for (i = 0; i < host->port_count; ++i) {
        const cmaper_nmap_xml_port_t *port = &host->ports[i];

        if (port->portid <= 0 || port->protocol == NULL || port->state == NULL) {
            continue;
        }
        if (strcmp(port->protocol, "tcp") != 0) {
            continue;
        }
        if (strcmp(port->state, "open") != 0) {
            continue;
        }

        if (count == capacity) {
            size_t next_capacity = capacity == 0 ? 16U : capacity * 2U;
            int *next_ports = (int *) realloc(ports, next_capacity * sizeof(int));
            if (next_ports == NULL) {
                if (ports != NULL) {
                    free(ports);
                }
                return CMAPER_ERR_OOM;
            }
            ports = next_ports;
            capacity = next_capacity;
        }

        ports[count++] = port->portid;
    }

    if (count == 0) {
        return CMAPER_OK;
    }

    qsort(ports, count, sizeof(int), cmaper_nmap_int_compare);

    unique_count = 1;
    for (i = 1; i < count; ++i) {
        if (ports[i] != ports[unique_count - 1]) {
            ports[unique_count++] = ports[i];
        }
    }

    if (unique_count != count) {
        int *shrunk = (int *) realloc(ports, unique_count * sizeof(int));
        if (shrunk != NULL) {
            ports = shrunk;
        }
    }

    *out_ports = ports;
    *out_count = unique_count;
    return CMAPER_OK;
}

int cmaper_nmap_ip_compare(const char *left, const char *right) {
    int left_family;
    int right_family;

    if (left == NULL && right == NULL) {
        return 0;
    }
    if (left == NULL) {
        return -1;
    }
    if (right == NULL) {
        return 1;
    }

    left_family = cmaper_nmap_ip_family(left);
    right_family = cmaper_nmap_ip_family(right);

    if (left_family != right_family) {
        if (left_family == AF_INET) {
            return -1;
        }
        if (right_family == AF_INET) {
            return 1;
        }
        if (left_family == AF_INET6) {
            return -1;
        }
        if (right_family == AF_INET6) {
            return 1;
        }
        return strcmp(left, right);
    }

    if (left_family == AF_INET) {
        struct in_addr left_addr;
        struct in_addr right_addr;

        if (inet_pton(AF_INET, left, &left_addr) == 1
            && inet_pton(AF_INET, right, &right_addr) == 1) {
            int cmp = memcmp(&left_addr, &right_addr, sizeof(left_addr));
            if (cmp != 0) {
                return cmp;
            }
            return 0;
        }
    } else if (left_family == AF_INET6) {
        struct in6_addr left_addr6;
        struct in6_addr right_addr6;

        if (inet_pton(AF_INET6, left, &left_addr6) == 1
            && inet_pton(AF_INET6, right, &right_addr6) == 1) {
            int cmp = memcmp(&left_addr6, &right_addr6, sizeof(left_addr6));
            if (cmp != 0) {
                return cmp;
            }
            return 0;
        }
    }

    return strcmp(left, right);
}
