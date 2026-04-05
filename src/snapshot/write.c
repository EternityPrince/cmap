#include "cmaper/snapshot/write.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmaper/scan/nmap_xml_parse.h"
#include "cmaper/scan/nmap_xml_utils.h"
#include "cmaper/security/nmap_extract.h"
#include "cmaper/snapshot/security.h"

#define CMAPER_SNAPSHOT_IP_CAP 64
#define CMAPER_SNAPSHOT_KEY_CAP 160
#define CMAPER_SNAPSHOT_NETWORK_CAP 256

typedef struct {
    char ip[CMAPER_SNAPSHOT_IP_CAP];
    char xml_path[CMAPER_SCAN_ARTIFACT_PATH_CAP];
    cmaper_nmap_xml_document_t document;
    const cmaper_nmap_xml_host_t *host;
    bool loaded;
} cmaper_snapshot_detail_doc_t;

typedef struct {
    char ip[CMAPER_SNAPSHOT_IP_CAP];
    const cmaper_nmap_xml_host_t *discovery_host;
    const cmaper_snapshot_detail_doc_t *detail_doc;
} cmaper_snapshot_merged_host_t;

static cmaper_err_t cmaper_snapshot_prepare(
    sqlite3 *db,
    const char *sql,
    sqlite3_stmt **out_stmt
) {
    int rc;

    if (db == NULL || sql == NULL || out_stmt == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    *out_stmt = NULL;
    rc = sqlite3_prepare_v2(db, sql, -1, out_stmt, NULL);
    if (rc != SQLITE_OK) {
        return CMAPER_ERR_IO;
    }

    return CMAPER_OK;
}

static void cmaper_snapshot_finalize(sqlite3_stmt **stmt) {
    if (stmt == NULL || *stmt == NULL) {
        return;
    }

    sqlite3_finalize(*stmt);
    *stmt = NULL;
}

static cmaper_err_t cmaper_snapshot_bind_text(
    sqlite3_stmt *stmt,
    int index,
    const char *value
) {
    int rc;

    if (stmt == NULL || value == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = sqlite3_bind_text(stmt, index, value, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        return CMAPER_ERR_IO;
    }

    return CMAPER_OK;
}

static cmaper_err_t cmaper_snapshot_bind_text_or_null(
    sqlite3_stmt *stmt,
    int index,
    const char *value
) {
    int rc;

    if (stmt == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    if (value == NULL || value[0] == '\0') {
        rc = sqlite3_bind_null(stmt, index);
    } else {
        rc = sqlite3_bind_text(stmt, index, value, -1, SQLITE_TRANSIENT);
    }
    if (rc != SQLITE_OK) {
        return CMAPER_ERR_IO;
    }

    return CMAPER_OK;
}

static cmaper_err_t cmaper_snapshot_bind_int(sqlite3_stmt *stmt, int index, int value) {
    int rc;

    if (stmt == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = sqlite3_bind_int(stmt, index, value);
    if (rc != SQLITE_OK) {
        return CMAPER_ERR_IO;
    }

    return CMAPER_OK;
}

static cmaper_err_t cmaper_snapshot_bind_int64(sqlite3_stmt *stmt, int index, sqlite3_int64 value) {
    int rc;

    if (stmt == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = sqlite3_bind_int64(stmt, index, value);
    if (rc != SQLITE_OK) {
        return CMAPER_ERR_IO;
    }

    return CMAPER_OK;
}

static cmaper_err_t cmaper_snapshot_step_done(sqlite3_stmt *stmt) {
    int rc;

    if (stmt == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        return CMAPER_ERR_IO;
    }

    return CMAPER_OK;
}

static cmaper_err_t cmaper_snapshot_step_row(sqlite3_stmt *stmt) {
    int rc;

    if (stmt == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        return CMAPER_ERR_IO;
    }

    return CMAPER_OK;
}

static cmaper_err_t cmaper_snapshot_exec(sqlite3 *db, const char *sql) {
    int rc;

    if (db == NULL || sql == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = sqlite3_exec(db, sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        return CMAPER_ERR_IO;
    }

    return CMAPER_OK;
}

static void cmaper_snapshot_detail_docs_dispose(
    cmaper_snapshot_detail_doc_t *items,
    size_t count
) {
    size_t i;

    if (items == NULL) {
        return;
    }

    for (i = 0; i < count; ++i) {
        if (items[i].loaded) {
            cmaper_nmap_xml_document_dispose(&items[i].document);
            cmaper_nmap_xml_document_init(&items[i].document);
            items[i].loaded = false;
        }
    }

    free(items);
}

static void cmaper_snapshot_merged_hosts_dispose(cmaper_snapshot_merged_host_t *items) {
    if (items == NULL) {
        return;
    }

    free(items);
}

static cmaper_err_t cmaper_snapshot_read_file(
    const char *path,
    char **out_data,
    size_t *out_size
) {
    FILE *file;
    long file_size_long;
    size_t file_size;
    char *buffer;
    size_t read_size;

    if (path == NULL || out_data == NULL || out_size == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    *out_data = NULL;
    *out_size = 0;

    file = fopen(path, "rb");
    if (file == NULL) {
        return CMAPER_ERR_IO;
    }

    if (fseek(file, 0L, SEEK_END) != 0) {
        fclose(file);
        return CMAPER_ERR_IO;
    }

    file_size_long = ftell(file);
    if (file_size_long < 0) {
        fclose(file);
        return CMAPER_ERR_IO;
    }
    file_size = (size_t) file_size_long;

    if (fseek(file, 0L, SEEK_SET) != 0) {
        fclose(file);
        return CMAPER_ERR_IO;
    }

    buffer = (char *) malloc(file_size + 1U);
    if (buffer == NULL) {
        fclose(file);
        return CMAPER_ERR_OOM;
    }

    read_size = fread(buffer, 1, file_size, file);
    if (read_size != file_size) {
        free(buffer);
        fclose(file);
        return CMAPER_ERR_IO;
    }

    if (fclose(file) != 0) {
        free(buffer);
        return CMAPER_ERR_IO;
    }

    buffer[file_size] = '\0';
    *out_data = buffer;
    *out_size = file_size;
    return CMAPER_OK;
}

static const cmaper_nmap_xml_host_t *cmaper_snapshot_find_host_in_document(
    const cmaper_nmap_xml_document_t *document,
    const char *expected_ip
) {
    const cmaper_nmap_xml_host_t *fallback_up = NULL;
    size_t i;

    if (document == NULL) {
        return NULL;
    }

    for (i = 0; i < document->host_count; ++i) {
        const cmaper_nmap_xml_host_t *host = &document->hosts[i];
        const char *ip = cmaper_nmap_host_primary_ip(host);
        if (ip != NULL && expected_ip != NULL && strcmp(ip, expected_ip) == 0) {
            return host;
        }
        if (fallback_up == NULL && host->status.state != NULL
            && strcmp(host->status.state, "up") == 0) {
            fallback_up = host;
        }
    }

    if (fallback_up != NULL) {
        return fallback_up;
    }
    if (document->host_count > 0) {
        return &document->hosts[0];
    }

    return NULL;
}

static int cmaper_snapshot_merged_host_compare(const void *left, const void *right) {
    const cmaper_snapshot_merged_host_t *a = (const cmaper_snapshot_merged_host_t *) left;
    const cmaper_snapshot_merged_host_t *b = (const cmaper_snapshot_merged_host_t *) right;
    return cmaper_nmap_ip_compare(a->ip, b->ip);
}

static void cmaper_snapshot_normalize_mac(
    const char *value,
    char *out,
    size_t out_cap
) {
    size_t i;

    if (out == NULL || out_cap == 0) {
        return;
    }

    out[0] = '\0';
    if (value == NULL || value[0] == '\0') {
        return;
    }

    if (snprintf(out, out_cap, "%s", value) >= (int) out_cap) {
        out[0] = '\0';
        return;
    }

    for (i = 0; out[i] != '\0'; ++i) {
        unsigned char ch = (unsigned char) out[i];
        if (ch == '-') {
            out[i] = ':';
        } else {
            out[i] = (char) toupper(ch);
        }
    }
}

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

static bool cmaper_snapshot_is_ipv4(const char *ip) {
    struct in_addr addr;
    return ip != NULL && inet_pton(AF_INET, ip, &addr) == 1;
}

static bool cmaper_snapshot_is_ipv6(const char *ip) {
    struct in6_addr addr;
    return ip != NULL && inet_pton(AF_INET6, ip, &addr) == 1;
}

static void cmaper_snapshot_make_network_token(
    const char *token,
    char *out,
    size_t out_cap
) {
    if (out == NULL || out_cap == 0) {
        return;
    }

    out[0] = '\0';
    if (token == NULL || token[0] == '\0') {
        return;
    }

    if (strchr(token, '/') != NULL) {
        snprintf(out, out_cap, "%s", token);
        return;
    }

    if (cmaper_snapshot_is_ipv4(token)) {
        snprintf(out, out_cap, "%s/32", token);
        return;
    }

    if (cmaper_snapshot_is_ipv6(token)) {
        snprintf(out, out_cap, "%s/128", token);
        return;
    }

    snprintf(out, out_cap, "%s", token);
}

static cmaper_err_t cmaper_snapshot_get_session_id(
    sqlite3 *db,
    const char *session_uid,
    sqlite3_int64 *out_session_id
) {
    static const char *SQL = "SELECT id FROM scan_sessions WHERE session_uid=?;";
    sqlite3_stmt *stmt = NULL;
    cmaper_err_t rc;

    if (db == NULL || session_uid == NULL || out_session_id == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    *out_session_id = 0;

    rc = cmaper_snapshot_prepare(db, SQL, &stmt);
    if (rc != CMAPER_OK) {
        return rc;
    }

    rc = cmaper_snapshot_bind_text(stmt, 1, session_uid);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    rc = cmaper_snapshot_step_row(stmt);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    *out_session_id = sqlite3_column_int64(stmt, 0);
    rc = CMAPER_OK;

cleanup:
    cmaper_snapshot_finalize(&stmt);
    return rc;
}

static cmaper_err_t cmaper_snapshot_upsert_network(
    sqlite3 *db,
    sqlite3_int64 session_id,
    const char *network_token
) {
    static const char *SQL_NETWORK =
        "INSERT INTO networks(cidr, first_seen_session_id, last_seen_session_id) "
        "VALUES(?, ?, ?) "
        "ON CONFLICT(cidr) DO UPDATE SET last_seen_session_id=excluded.last_seen_session_id;";
    static const char *SQL_NETWORK_ID =
        "SELECT id FROM networks WHERE cidr=?;";
    static const char *SQL_LINK =
        "INSERT OR IGNORE INTO session_networks(session_id, network_id) VALUES(?, ?);";
    sqlite3_stmt *stmt_network = NULL;
    sqlite3_stmt *stmt_network_id = NULL;
    sqlite3_stmt *stmt_link = NULL;
    sqlite3_int64 network_id = 0;
    cmaper_err_t rc;

    if (db == NULL || network_token == NULL || network_token[0] == '\0') {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = cmaper_snapshot_prepare(db, SQL_NETWORK, &stmt_network);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text(stmt_network, 1, network_token);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_int64(stmt_network, 2, session_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_int64(stmt_network, 3, session_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_step_done(stmt_network);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    rc = cmaper_snapshot_prepare(db, SQL_NETWORK_ID, &stmt_network_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text(stmt_network_id, 1, network_token);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_step_row(stmt_network_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    network_id = sqlite3_column_int64(stmt_network_id, 0);

    rc = cmaper_snapshot_prepare(db, SQL_LINK, &stmt_link);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_int64(stmt_link, 1, session_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_int64(stmt_link, 2, network_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_step_done(stmt_link);

cleanup:
    cmaper_snapshot_finalize(&stmt_network);
    cmaper_snapshot_finalize(&stmt_network_id);
    cmaper_snapshot_finalize(&stmt_link);
    return rc;
}

static cmaper_err_t cmaper_snapshot_upsert_session_networks(
    sqlite3 *db,
    sqlite3_int64 session_id,
    const char *target_expression
) {
    size_t i = 0;
    char token[CMAPER_SNAPSHOT_NETWORK_CAP];
    size_t token_len = 0;
    cmaper_err_t rc = CMAPER_OK;

    if (db == NULL || target_expression == NULL || target_expression[0] == '\0') {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    while (true) {
        char ch = target_expression[i];
        bool is_delim = (ch == '\0' || ch == ',' || isspace((unsigned char) ch));

        if (!is_delim && token_len + 1U < sizeof(token)) {
            token[token_len++] = ch;
        }

        if (is_delim && token_len > 0) {
            char network_token[CMAPER_SNAPSHOT_NETWORK_CAP];
            token[token_len] = '\0';
            cmaper_snapshot_make_network_token(token, network_token, sizeof(network_token));
            if (network_token[0] != '\0') {
                rc = cmaper_snapshot_upsert_network(db, session_id, network_token);
                if (rc != CMAPER_OK) {
                    return rc;
                }
            }
            token_len = 0;
        }

        if (ch == '\0') {
            break;
        }

        i += 1U;
    }

    return CMAPER_OK;
}

static cmaper_err_t cmaper_snapshot_find_device_by_mac(
    sqlite3 *db,
    const char *mac_address,
    sqlite3_int64 *out_device_id
) {
    static const char *SQL = "SELECT id FROM devices WHERE mac_address=? LIMIT 1;";
    sqlite3_stmt *stmt = NULL;
    cmaper_err_t rc;
    int step_rc;

    if (db == NULL || mac_address == NULL || out_device_id == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    *out_device_id = 0;

    rc = cmaper_snapshot_prepare(db, SQL, &stmt);
    if (rc != CMAPER_OK) {
        return rc;
    }

    rc = cmaper_snapshot_bind_text(stmt, 1, mac_address);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    step_rc = sqlite3_step(stmt);
    if (step_rc == SQLITE_ROW) {
        *out_device_id = sqlite3_column_int64(stmt, 0);
        rc = CMAPER_OK;
    } else if (step_rc == SQLITE_DONE) {
        rc = CMAPER_OK;
    } else {
        rc = CMAPER_ERR_IO;
    }

cleanup:
    cmaper_snapshot_finalize(&stmt);
    return rc;
}

static cmaper_err_t cmaper_snapshot_find_device_by_previous_ip(
    sqlite3 *db,
    const char *ip_address,
    sqlite3_int64 *out_device_id
) {
    static const char *SQL =
        "SELECT d.id "
        "FROM devices d "
        "JOIN device_ip_addresses dip ON dip.device_id=d.id "
        "WHERE dip.ip_address=? AND dip.is_current=1 "
        "ORDER BY COALESCE(dip.last_seen_session_id, 0) DESC "
        "LIMIT 1;";
    sqlite3_stmt *stmt = NULL;
    cmaper_err_t rc;
    int step_rc;

    if (db == NULL || ip_address == NULL || out_device_id == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    *out_device_id = 0;

    rc = cmaper_snapshot_prepare(db, SQL, &stmt);
    if (rc != CMAPER_OK) {
        return rc;
    }

    rc = cmaper_snapshot_bind_text(stmt, 1, ip_address);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    step_rc = sqlite3_step(stmt);
    if (step_rc == SQLITE_ROW) {
        *out_device_id = sqlite3_column_int64(stmt, 0);
        rc = CMAPER_OK;
    } else if (step_rc == SQLITE_DONE) {
        rc = CMAPER_OK;
    } else {
        rc = CMAPER_ERR_IO;
    }

cleanup:
    cmaper_snapshot_finalize(&stmt);
    return rc;
}

static cmaper_err_t cmaper_snapshot_find_device_by_fallback_key(
    sqlite3 *db,
    const char *fallback_key,
    sqlite3_int64 *out_device_id
) {
    static const char *SQL = "SELECT id FROM devices WHERE fallback_key=? LIMIT 1;";
    sqlite3_stmt *stmt = NULL;
    cmaper_err_t rc;
    int step_rc;

    if (db == NULL || fallback_key == NULL || out_device_id == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    *out_device_id = 0;

    rc = cmaper_snapshot_prepare(db, SQL, &stmt);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_snapshot_bind_text(stmt, 1, fallback_key);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    step_rc = sqlite3_step(stmt);
    if (step_rc == SQLITE_ROW) {
        *out_device_id = sqlite3_column_int64(stmt, 0);
        rc = CMAPER_OK;
    } else if (step_rc == SQLITE_DONE) {
        rc = CMAPER_OK;
    } else {
        rc = CMAPER_ERR_IO;
    }

cleanup:
    cmaper_snapshot_finalize(&stmt);
    return rc;
}

static cmaper_err_t cmaper_snapshot_insert_device(
    sqlite3 *db,
    const char *stable_key,
    const char *fallback_key,
    const char *mac_address,
    const char *mac_vendor,
    sqlite3_int64 session_id,
    sqlite3_int64 *out_device_id
) {
    static const char *SQL =
        "INSERT INTO devices("
        "  stable_key, fallback_key, mac_address, mac_vendor,"
        "  first_seen_session_id, last_seen_session_id, updated_at"
        ") VALUES(?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'));";
    sqlite3_stmt *stmt = NULL;
    cmaper_err_t rc;

    if (db == NULL || stable_key == NULL || fallback_key == NULL || out_device_id == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = cmaper_snapshot_prepare(db, SQL, &stmt);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_snapshot_bind_text(stmt, 1, stable_key);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text(stmt, 2, fallback_key);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text_or_null(stmt, 3, mac_address);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text_or_null(stmt, 4, mac_vendor);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_int64(stmt, 5, session_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_int64(stmt, 6, session_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_step_done(stmt);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    *out_device_id = sqlite3_last_insert_rowid(db);
    rc = CMAPER_OK;

cleanup:
    cmaper_snapshot_finalize(&stmt);
    return rc;
}

static cmaper_err_t cmaper_snapshot_update_device(
    sqlite3 *db,
    sqlite3_int64 device_id,
    sqlite3_int64 session_id,
    const char *mac_address,
    const char *mac_vendor
) {
    static const char *SQL =
        "UPDATE devices "
        "SET last_seen_session_id=?, "
        "    mac_address=COALESCE(mac_address, ?), "
        "    mac_vendor=COALESCE(mac_vendor, ?), "
        "    updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') "
        "WHERE id=?;";
    sqlite3_stmt *stmt = NULL;
    cmaper_err_t rc;

    if (db == NULL || device_id <= 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = cmaper_snapshot_prepare(db, SQL, &stmt);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_snapshot_bind_int64(stmt, 1, session_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text_or_null(stmt, 2, mac_address);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text_or_null(stmt, 3, mac_vendor);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_int64(stmt, 4, device_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_step_done(stmt);

cleanup:
    cmaper_snapshot_finalize(&stmt);
    return rc;
}

static cmaper_err_t cmaper_snapshot_upsert_device_ip(
    sqlite3 *db,
    sqlite3_int64 device_id,
    const char *ip_address,
    const char *address_type,
    sqlite3_int64 session_id
) {
    static const char *SQL_MARK_OLD =
        "UPDATE device_ip_addresses SET is_current=0 "
        "WHERE device_id=? AND ip_address<>?;";
    static const char *SQL_UPSERT =
        "INSERT INTO device_ip_addresses("
        "  device_id, ip_address, address_type, first_seen_session_id, last_seen_session_id, is_current"
        ") VALUES(?, ?, ?, ?, ?, 1) "
        "ON CONFLICT(device_id, ip_address) DO UPDATE SET "
        "  address_type=excluded.address_type, "
        "  last_seen_session_id=excluded.last_seen_session_id, "
        "  is_current=1;";
    sqlite3_stmt *stmt_old = NULL;
    sqlite3_stmt *stmt_upsert = NULL;
    cmaper_err_t rc;

    if (db == NULL || device_id <= 0 || ip_address == NULL || ip_address[0] == '\0') {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = cmaper_snapshot_prepare(db, SQL_MARK_OLD, &stmt_old);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_int64(stmt_old, 1, device_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text(stmt_old, 2, ip_address);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_step_done(stmt_old);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    rc = cmaper_snapshot_prepare(db, SQL_UPSERT, &stmt_upsert);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_int64(stmt_upsert, 1, device_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text(stmt_upsert, 2, ip_address);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text_or_null(stmt_upsert, 3, address_type);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_int64(stmt_upsert, 4, session_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_int64(stmt_upsert, 5, session_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_step_done(stmt_upsert);

cleanup:
    cmaper_snapshot_finalize(&stmt_old);
    cmaper_snapshot_finalize(&stmt_upsert);
    return rc;
}

static void cmaper_snapshot_make_keys(
    const char *primary_ip,
    const char *mac_address,
    char *out_stable_key,
    size_t stable_cap,
    char *out_fallback_key,
    size_t fallback_cap
) {
    if (out_stable_key != NULL && stable_cap > 0) {
        out_stable_key[0] = '\0';
    }
    if (out_fallback_key != NULL && fallback_cap > 0) {
        out_fallback_key[0] = '\0';
    }

    if (out_fallback_key != NULL && fallback_cap > 0) {
        if (primary_ip != NULL && primary_ip[0] != '\0') {
            snprintf(out_fallback_key, fallback_cap, "ip:%s", primary_ip);
        } else {
            snprintf(out_fallback_key, fallback_cap, "unknown");
        }
    }

    if (out_stable_key != NULL && stable_cap > 0) {
        if (mac_address != NULL && mac_address[0] != '\0') {
            snprintf(out_stable_key, stable_cap, "mac:%s", mac_address);
        } else if (out_fallback_key != NULL && out_fallback_key[0] != '\0') {
            snprintf(out_stable_key, stable_cap, "%s", out_fallback_key);
        } else {
            snprintf(out_stable_key, stable_cap, "unknown");
        }
    }
}

static cmaper_err_t cmaper_snapshot_resolve_device(
    sqlite3 *db,
    sqlite3_int64 session_id,
    const char *primary_ip,
    const char *address_type,
    const char *mac_address,
    const char *mac_vendor,
    sqlite3_int64 *out_device_id
) {
    char normalized_mac[CMAPER_SCAN_SOURCE_MAC_CAP];
    char stable_key[CMAPER_SNAPSHOT_KEY_CAP];
    char fallback_key[CMAPER_SNAPSHOT_KEY_CAP];
    sqlite3_int64 device_id = 0;
    cmaper_err_t rc;

    if (db == NULL || primary_ip == NULL || primary_ip[0] == '\0' || out_device_id == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    *out_device_id = 0;

    cmaper_snapshot_normalize_mac(mac_address, normalized_mac, sizeof(normalized_mac));
    cmaper_snapshot_make_keys(
        primary_ip,
        normalized_mac[0] != '\0' ? normalized_mac : NULL,
        stable_key,
        sizeof(stable_key),
        fallback_key,
        sizeof(fallback_key)
    );

    if (normalized_mac[0] != '\0') {
        rc = cmaper_snapshot_find_device_by_mac(db, normalized_mac, &device_id);
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    if (device_id <= 0) {
        rc = cmaper_snapshot_find_device_by_previous_ip(db, primary_ip, &device_id);
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    if (device_id <= 0) {
        rc = cmaper_snapshot_find_device_by_fallback_key(db, fallback_key, &device_id);
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    if (device_id <= 0) {
        rc = cmaper_snapshot_insert_device(
            db,
            stable_key,
            fallback_key,
            normalized_mac[0] != '\0' ? normalized_mac : NULL,
            mac_vendor,
            session_id,
            &device_id
        );
        if (rc != CMAPER_OK) {
            return rc;
        }
    } else {
        rc = cmaper_snapshot_update_device(
            db,
            device_id,
            session_id,
            normalized_mac[0] != '\0' ? normalized_mac : NULL,
            mac_vendor
        );
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    rc = cmaper_snapshot_upsert_device_ip(
        db,
        device_id,
        primary_ip,
        address_type,
        session_id
    );
    if (rc != CMAPER_OK) {
        return rc;
    }

    *out_device_id = device_id;
    return CMAPER_OK;
}

static cmaper_err_t cmaper_snapshot_upsert_host_observation(
    sqlite3 *db,
    sqlite3_int64 session_id,
    sqlite3_int64 device_id,
    const char *primary_ip,
    const char *primary_ip_type,
    const char *status,
    const char *source,
    const char *hostname_primary,
    const char *mac_address,
    const char *mac_vendor,
    const char *detail_xml_path,
    sqlite3_int64 *out_host_observation_id
) {
    static const char *SQL_UPSERT =
        "INSERT INTO host_observations("
        "  session_id, device_id, primary_ip, primary_ip_type, status, observation_source,"
        "  hostname_primary, mac_address, mac_vendor, detail_xml_path"
        ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(session_id, device_id, primary_ip) DO UPDATE SET "
        "  primary_ip_type=excluded.primary_ip_type, "
        "  status=excluded.status, "
        "  observation_source=excluded.observation_source, "
        "  hostname_primary=excluded.hostname_primary, "
        "  mac_address=excluded.mac_address, "
        "  mac_vendor=excluded.mac_vendor, "
        "  detail_xml_path=excluded.detail_xml_path;";
    static const char *SQL_SELECT_ID =
        "SELECT id FROM host_observations WHERE session_id=? AND device_id=? AND primary_ip=?;";
    sqlite3_stmt *stmt_upsert = NULL;
    sqlite3_stmt *stmt_id = NULL;
    cmaper_err_t rc;

    if (db == NULL || primary_ip == NULL || source == NULL || out_host_observation_id == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    *out_host_observation_id = 0;

    rc = cmaper_snapshot_prepare(db, SQL_UPSERT, &stmt_upsert);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_int64(stmt_upsert, 1, session_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_int64(stmt_upsert, 2, device_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text(stmt_upsert, 3, primary_ip);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text_or_null(stmt_upsert, 4, primary_ip_type);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text_or_null(stmt_upsert, 5, status);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text(stmt_upsert, 6, source);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text_or_null(stmt_upsert, 7, hostname_primary);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text_or_null(stmt_upsert, 8, mac_address);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text_or_null(stmt_upsert, 9, mac_vendor);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text_or_null(stmt_upsert, 10, detail_xml_path);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_step_done(stmt_upsert);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    rc = cmaper_snapshot_prepare(db, SQL_SELECT_ID, &stmt_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_int64(stmt_id, 1, session_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_int64(stmt_id, 2, device_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text(stmt_id, 3, primary_ip);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_step_row(stmt_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    *out_host_observation_id = sqlite3_column_int64(stmt_id, 0);
    rc = CMAPER_OK;

cleanup:
    cmaper_snapshot_finalize(&stmt_upsert);
    cmaper_snapshot_finalize(&stmt_id);
    return rc;
}

static cmaper_err_t cmaper_snapshot_clear_host_children(
    sqlite3 *db,
    sqlite3_int64 host_observation_id
) {
    static const char *SQL_DELETE_TLS =
        "DELETE FROM tls_fingerprints WHERE host_observation_id=?;";
    static const char *SQL_DELETE_SSH =
        "DELETE FROM ssh_fingerprints WHERE host_observation_id=?;";
    static const char *SQL_DELETE_HTTP =
        "DELETE FROM http_fingerprints WHERE host_observation_id=?;";
    static const char *SQL_DELETE_SMB =
        "DELETE FROM smb_fingerprints WHERE host_observation_id=?;";
    static const char *SQL_DELETE_FINDINGS =
        "DELETE FROM vulnerability_findings WHERE host_observation_id=?;";
    static const char *SQL_DELETE_SURFACES =
        "DELETE FROM management_surfaces WHERE host_observation_id=?;";
    static const char *SQL_DELETE_HOST_SCRIPTS =
        "DELETE FROM script_results WHERE host_observation_id=?;";
    static const char *SQL_DELETE_SERVICES =
        "DELETE FROM service_observations WHERE host_observation_id=?;";
    static const char *SQL_DELETE_OS =
        "DELETE FROM os_matches WHERE host_observation_id=?;";
    static const char *SQL_DELETE_TRACES =
        "DELETE FROM traces WHERE host_observation_id=?;";
    sqlite3_stmt *stmt = NULL;
    const char *sql_list[10];
    size_t i;
    cmaper_err_t rc = CMAPER_OK;

    if (db == NULL || host_observation_id <= 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    sql_list[0] = SQL_DELETE_TLS;
    sql_list[1] = SQL_DELETE_SSH;
    sql_list[2] = SQL_DELETE_HTTP;
    sql_list[3] = SQL_DELETE_SMB;
    sql_list[4] = SQL_DELETE_FINDINGS;
    sql_list[5] = SQL_DELETE_SURFACES;
    sql_list[6] = SQL_DELETE_HOST_SCRIPTS;
    sql_list[7] = SQL_DELETE_SERVICES;
    sql_list[8] = SQL_DELETE_OS;
    sql_list[9] = SQL_DELETE_TRACES;

    for (i = 0; i < 10; ++i) {
        rc = cmaper_snapshot_prepare(db, sql_list[i], &stmt);
        if (rc != CMAPER_OK) {
            goto cleanup;
        }
        rc = cmaper_snapshot_bind_int64(stmt, 1, host_observation_id);
        if (rc != CMAPER_OK) {
            goto cleanup;
        }
        rc = cmaper_snapshot_step_done(stmt);
        if (rc != CMAPER_OK) {
            goto cleanup;
        }
        cmaper_snapshot_finalize(&stmt);
    }

cleanup:
    cmaper_snapshot_finalize(&stmt);
    return rc;
}

static cmaper_err_t cmaper_snapshot_find_or_create_port_id(
    sqlite3 *db,
    const char *protocol,
    int port_number,
    sqlite3_int64 *out_port_id
) {
    static const char *SQL_INSERT =
        "INSERT INTO ports(protocol, port_number) VALUES(?, ?) "
        "ON CONFLICT(protocol, port_number) DO NOTHING;";
    static const char *SQL_SELECT = "SELECT id FROM ports WHERE protocol=? AND port_number=?;";
    sqlite3_stmt *stmt_insert = NULL;
    sqlite3_stmt *stmt_select = NULL;
    cmaper_err_t rc;

    if (db == NULL || protocol == NULL || out_port_id == NULL || port_number <= 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    *out_port_id = 0;

    rc = cmaper_snapshot_prepare(db, SQL_INSERT, &stmt_insert);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text(stmt_insert, 1, protocol);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_int(stmt_insert, 2, port_number);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_step_done(stmt_insert);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    rc = cmaper_snapshot_prepare(db, SQL_SELECT, &stmt_select);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text(stmt_select, 1, protocol);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_int(stmt_select, 2, port_number);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_step_row(stmt_select);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    *out_port_id = sqlite3_column_int64(stmt_select, 0);
    rc = CMAPER_OK;

cleanup:
    cmaper_snapshot_finalize(&stmt_insert);
    cmaper_snapshot_finalize(&stmt_select);
    return rc;
}

static cmaper_err_t cmaper_snapshot_upsert_service_observation(
    sqlite3 *db,
    sqlite3_int64 host_observation_id,
    sqlite3_int64 port_id,
    const cmaper_nmap_xml_port_t *port,
    sqlite3_int64 *out_service_observation_id
) {
    static const char *SQL_UPSERT =
        "INSERT INTO service_observations("
        "  host_observation_id, port_id, state, reason, service_name, service_product, service_version"
        ") VALUES(?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(host_observation_id, port_id) DO UPDATE SET "
        "  state=excluded.state, "
        "  reason=excluded.reason, "
        "  service_name=excluded.service_name, "
        "  service_product=excluded.service_product, "
        "  service_version=excluded.service_version;";
    static const char *SQL_SELECT =
        "SELECT id FROM service_observations WHERE host_observation_id=? AND port_id=?;";
    sqlite3_stmt *stmt_upsert = NULL;
    sqlite3_stmt *stmt_select = NULL;
    cmaper_err_t rc;

    if (db == NULL || port == NULL || out_service_observation_id == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    *out_service_observation_id = 0;

    rc = cmaper_snapshot_prepare(db, SQL_UPSERT, &stmt_upsert);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_int64(stmt_upsert, 1, host_observation_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_int64(stmt_upsert, 2, port_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text_or_null(stmt_upsert, 3, port->state);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text_or_null(stmt_upsert, 4, port->reason);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text_or_null(stmt_upsert, 5, port->service_name);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text_or_null(stmt_upsert, 6, port->service_product);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text_or_null(stmt_upsert, 7, port->service_version);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_step_done(stmt_upsert);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    rc = cmaper_snapshot_prepare(db, SQL_SELECT, &stmt_select);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_int64(stmt_select, 1, host_observation_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_int64(stmt_select, 2, port_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_step_row(stmt_select);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    *out_service_observation_id = sqlite3_column_int64(stmt_select, 0);
    rc = CMAPER_OK;

cleanup:
    cmaper_snapshot_finalize(&stmt_upsert);
    cmaper_snapshot_finalize(&stmt_select);
    return rc;
}

static cmaper_err_t cmaper_snapshot_insert_script_result(
    sqlite3 *db,
    sqlite3_int64 host_observation_id,
    sqlite3_int64 service_observation_id,
    const char *script_id,
    const char *output
) {
    static const char *SQL =
        "INSERT INTO script_results("
        "  host_observation_id, service_observation_id, script_id, output"
        ") VALUES(?, ?, ?, ?);";
    sqlite3_stmt *stmt = NULL;
    cmaper_err_t rc;

    if (db == NULL || script_id == NULL || script_id[0] == '\0') {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = cmaper_snapshot_prepare(db, SQL, &stmt);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_snapshot_bind_int64(stmt, 1, host_observation_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    if (service_observation_id > 0) {
        rc = cmaper_snapshot_bind_int64(stmt, 2, service_observation_id);
    } else {
        rc = cmaper_snapshot_bind_text_or_null(stmt, 2, NULL);
    }
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text(stmt, 3, script_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text_or_null(stmt, 4, output);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_step_done(stmt);

cleanup:
    cmaper_snapshot_finalize(&stmt);
    return rc;
}

static cmaper_err_t cmaper_snapshot_insert_os_match(
    sqlite3 *db,
    sqlite3_int64 host_observation_id,
    const cmaper_nmap_xml_osmatch_t *osmatch
) {
    static const char *SQL =
        "INSERT INTO os_matches(host_observation_id, name, accuracy, line) "
        "VALUES(?, ?, ?, ?);";
    sqlite3_stmt *stmt = NULL;
    cmaper_err_t rc;

    if (db == NULL || osmatch == NULL || osmatch->name == NULL || osmatch->name[0] == '\0') {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = cmaper_snapshot_prepare(db, SQL, &stmt);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_snapshot_bind_int64(stmt, 1, host_observation_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_text(stmt, 2, osmatch->name);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_int(stmt, 3, osmatch->accuracy);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_int(stmt, 4, osmatch->line);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_step_done(stmt);

cleanup:
    cmaper_snapshot_finalize(&stmt);
    return rc;
}

static cmaper_err_t cmaper_snapshot_insert_trace(
    sqlite3 *db,
    sqlite3_int64 host_observation_id,
    const cmaper_nmap_xml_trace_hop_t *hops,
    size_t hop_count
) {
    static const char *SQL_TRACE =
        "INSERT INTO traces(host_observation_id) VALUES(?);";
    static const char *SQL_HOP =
        "INSERT INTO trace_hops(trace_id, hop_index, ttl, ipaddr, rtt, host) "
        "VALUES(?, ?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt_trace = NULL;
    sqlite3_stmt *stmt_hop = NULL;
    sqlite3_int64 trace_id;
    size_t i;
    cmaper_err_t rc;

    if (db == NULL || hops == NULL || hop_count == 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = cmaper_snapshot_prepare(db, SQL_TRACE, &stmt_trace);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_bind_int64(stmt_trace, 1, host_observation_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_step_done(stmt_trace);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    trace_id = sqlite3_last_insert_rowid(db);

    rc = cmaper_snapshot_prepare(db, SQL_HOP, &stmt_hop);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    for (i = 0; i < hop_count; ++i) {
        sqlite3_reset(stmt_hop);
        sqlite3_clear_bindings(stmt_hop);

        rc = cmaper_snapshot_bind_int64(stmt_hop, 1, trace_id);
        if (rc != CMAPER_OK) {
            goto cleanup;
        }
        rc = cmaper_snapshot_bind_int(stmt_hop, 2, (int) (i + 1U));
        if (rc != CMAPER_OK) {
            goto cleanup;
        }
        rc = cmaper_snapshot_bind_int(stmt_hop, 3, hops[i].ttl);
        if (rc != CMAPER_OK) {
            goto cleanup;
        }
        rc = cmaper_snapshot_bind_text_or_null(stmt_hop, 4, hops[i].ipaddr);
        if (rc != CMAPER_OK) {
            goto cleanup;
        }
        rc = cmaper_snapshot_bind_text_or_null(stmt_hop, 5, hops[i].rtt);
        if (rc != CMAPER_OK) {
            goto cleanup;
        }
        rc = cmaper_snapshot_bind_text_or_null(stmt_hop, 6, hops[i].host);
        if (rc != CMAPER_OK) {
            goto cleanup;
        }
        rc = cmaper_snapshot_step_done(stmt_hop);
        if (rc != CMAPER_OK) {
            goto cleanup;
        }
    }

cleanup:
    cmaper_snapshot_finalize(&stmt_trace);
    cmaper_snapshot_finalize(&stmt_hop);
    return rc;
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

static cmaper_err_t cmaper_snapshot_persist_merged_host(
    sqlite3 *db,
    sqlite3_int64 session_id,
    const cmaper_snapshot_merged_host_t *merged,
    cmaper_logger_t *logger
) {
    const cmaper_nmap_xml_host_t *primary;
    const cmaper_nmap_xml_host_t *secondary;
    const cmaper_nmap_xml_address_t *mac;
    const cmaper_nmap_xml_port_t *ports = NULL;
    const cmaper_nmap_xml_script_t *host_scripts = NULL;
    const cmaper_nmap_xml_osmatch_t *os_matches = NULL;
    const cmaper_nmap_xml_trace_hop_t *trace_hops = NULL;
    const char *ip;
    const char *ip_type;
    const char *status;
    const char *hostname;
    sqlite3_int64 device_id = 0;
    sqlite3_int64 host_observation_id = 0;
    size_t port_count = 0;
    size_t host_script_count = 0;
    size_t os_count = 0;
    size_t trace_count = 0;
    size_t i;
    cmaper_err_t rc;
    cmaper_security_host_artifacts_t security_artifacts;

    if (db == NULL || merged == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    cmaper_security_host_artifacts_init(&security_artifacts);

    primary = cmaper_snapshot_pick_primary_host(merged);
    secondary = cmaper_snapshot_pick_secondary_host(merged);

    ip = merged->ip[0] != '\0' ? merged->ip : cmaper_nmap_host_primary_ip(primary);
    if (ip == NULL || ip[0] == '\0') {
        return CMAPER_ERR_PARSE;
    }

    ip_type = cmaper_snapshot_host_address_type_for_ip(primary, ip);
    if (ip_type == NULL) {
        ip_type = cmaper_snapshot_host_address_type_for_ip(secondary, ip);
    }
    status = cmaper_snapshot_pick_status(primary, secondary);
    hostname = cmaper_snapshot_pick_hostname(primary, secondary);
    mac = cmaper_snapshot_pick_mac(primary, secondary);

    rc = cmaper_snapshot_resolve_device(
        db,
        session_id,
        ip,
        ip_type,
        mac != NULL ? mac->addr : NULL,
        mac != NULL ? mac->vendor : NULL,
        &device_id
    );
    if (rc != CMAPER_OK) {
        return rc;
    }

    rc = cmaper_snapshot_upsert_host_observation(
        db,
        session_id,
        device_id,
        ip,
        ip_type,
        status,
        cmaper_snapshot_observation_source(merged),
        hostname,
        mac != NULL ? mac->addr : NULL,
        mac != NULL ? mac->vendor : NULL,
        merged->detail_doc != NULL ? merged->detail_doc->xml_path : NULL,
        &host_observation_id
    );
    if (rc != CMAPER_OK) {
        return rc;
    }

    rc = cmaper_snapshot_clear_host_children(db, host_observation_id);
    if (rc != CMAPER_OK) {
        return rc;
    }

    cmaper_snapshot_pick_os_view(primary, secondary, &os_matches, &os_count);
    for (i = 0; i < os_count; ++i) {
        rc = cmaper_snapshot_insert_os_match(db, host_observation_id, &os_matches[i]);
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    cmaper_snapshot_pick_script_view(primary, secondary, &host_scripts, &host_script_count);
    for (i = 0; i < host_script_count; ++i) {
        if (host_scripts[i].id == NULL || host_scripts[i].id[0] == '\0') {
            continue;
        }
        rc = cmaper_snapshot_insert_script_result(
            db,
            host_observation_id,
            0,
            host_scripts[i].id,
            host_scripts[i].output
        );
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    cmaper_snapshot_pick_port_view(primary, secondary, &ports, &port_count);
    for (i = 0; i < port_count; ++i) {
        sqlite3_int64 port_id = 0;
        sqlite3_int64 service_observation_id = 0;
        size_t script_index;

        if (ports[i].protocol == NULL || ports[i].protocol[0] == '\0' || ports[i].portid <= 0) {
            continue;
        }

        rc = cmaper_snapshot_find_or_create_port_id(
            db,
            ports[i].protocol,
            ports[i].portid,
            &port_id
        );
        if (rc != CMAPER_OK) {
            return rc;
        }

        rc = cmaper_snapshot_upsert_service_observation(
            db,
            host_observation_id,
            port_id,
            &ports[i],
            &service_observation_id
        );
        if (rc != CMAPER_OK) {
            return rc;
        }

        for (script_index = 0; script_index < ports[i].script_count; ++script_index) {
            const cmaper_nmap_xml_script_t *script = &ports[i].scripts[script_index];
            if (script->id == NULL || script->id[0] == '\0') {
                continue;
            }

            rc = cmaper_snapshot_insert_script_result(
                db,
                host_observation_id,
                service_observation_id,
                script->id,
                script->output
            );
            if (rc != CMAPER_OK) {
                return rc;
            }
        }
    }

    cmaper_snapshot_pick_trace_view(primary, secondary, &trace_hops, &trace_count);
    if (trace_count > 0 && trace_hops != NULL) {
        rc = cmaper_snapshot_insert_trace(db, host_observation_id, trace_hops, trace_count);
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    rc = cmaper_security_extract_from_host_pair(primary, secondary, &security_artifacts);
    if (rc != CMAPER_OK) {
        cmaper_security_host_artifacts_dispose(&security_artifacts);
        return rc;
    }

    rc = cmaper_snapshot_security_persist_host_artifacts(
        db,
        host_observation_id,
        &security_artifacts,
        logger
    );
    cmaper_security_host_artifacts_dispose(&security_artifacts);
    if (rc != CMAPER_OK) {
        return rc;
    }

    return CMAPER_OK;
}

static cmaper_err_t cmaper_snapshot_build_detail_docs(
    const cmaper_scan_result_t *scan_result,
    cmaper_snapshot_detail_doc_t **out_items,
    size_t *out_count,
    cmaper_logger_t *logger
) {
    size_t i;
    size_t capacity;
    size_t count = 0;
    cmaper_snapshot_detail_doc_t *items = NULL;

    if (scan_result == NULL || out_items == NULL || out_count == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    *out_items = NULL;
    *out_count = 0;

    capacity = scan_result->detail_result.host_count;
    if (capacity == 0) {
        return CMAPER_OK;
    }

    items = (cmaper_snapshot_detail_doc_t *) calloc(capacity, sizeof(cmaper_snapshot_detail_doc_t));
    if (items == NULL) {
        return CMAPER_ERR_OOM;
    }

    for (i = 0; i < scan_result->detail_result.host_count; ++i) {
        const cmaper_scan_detail_host_result_t *host_result = &scan_result->detail_result.hosts[i];
        char *xml_data = NULL;
        size_t xml_size = 0;
        cmaper_nmap_xml_diag_t xml_diag;
        cmaper_err_t rc;

        if (!host_result->success || host_result->xml_path[0] == '\0') {
            continue;
        }

        rc = cmaper_snapshot_read_file(host_result->xml_path, &xml_data, &xml_size);
        if (rc != CMAPER_OK) {
            cmaper_log(
                logger,
                CMAPER_LOG_WARN,
                "snapshot/write: failed to read host xml '%s'",
                host_result->xml_path
            );
            continue;
        }

        cmaper_nmap_xml_document_init(&items[count].document);
        cmaper_nmap_xml_diag_clear(&xml_diag);

        rc = cmaper_nmap_xml_parse_memory(
            xml_data,
            xml_size,
            &items[count].document,
            &xml_diag
        );
        free(xml_data);
        xml_data = NULL;

        if (rc != CMAPER_OK) {
            cmaper_log(
                logger,
                CMAPER_LOG_WARN,
                "snapshot/write: failed to parse host xml '%s': %s",
                host_result->xml_path,
                xml_diag.message[0] != '\0' ? xml_diag.message : "parse error"
            );
            cmaper_nmap_xml_document_dispose(&items[count].document);
            continue;
        }

        snprintf(items[count].ip, sizeof(items[count].ip), "%s", host_result->ip);
        snprintf(items[count].xml_path, sizeof(items[count].xml_path), "%s", host_result->xml_path);
        items[count].host = cmaper_snapshot_find_host_in_document(
            &items[count].document,
            host_result->ip
        );
        items[count].loaded = true;
        count += 1U;
    }

    *out_items = items;
    *out_count = count;
    return CMAPER_OK;
}

static const cmaper_snapshot_detail_doc_t *cmaper_snapshot_find_detail_doc_for_ip(
    const cmaper_snapshot_detail_doc_t *items,
    size_t count,
    const char *ip
) {
    size_t i;

    if (items == NULL || ip == NULL || ip[0] == '\0') {
        return NULL;
    }

    for (i = 0; i < count; ++i) {
        if (!items[i].loaded || items[i].ip[0] == '\0') {
            continue;
        }
        if (strcmp(items[i].ip, ip) == 0) {
            return &items[i];
        }
    }

    return NULL;
}

static cmaper_err_t cmaper_snapshot_append_or_merge_merged_host(
    cmaper_snapshot_merged_host_t **items,
    size_t *count,
    const char *ip,
    const cmaper_nmap_xml_host_t *discovery_host,
    const cmaper_snapshot_detail_doc_t *detail_doc
) {
    size_t i;
    cmaper_snapshot_merged_host_t *next;

    if (items == NULL || count == NULL || ip == NULL || ip[0] == '\0') {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    for (i = 0; i < *count; ++i) {
        if (strcmp((*items)[i].ip, ip) != 0) {
            continue;
        }

        if ((*items)[i].discovery_host == NULL && discovery_host != NULL) {
            (*items)[i].discovery_host = discovery_host;
        }
        if ((*items)[i].detail_doc == NULL && detail_doc != NULL) {
            (*items)[i].detail_doc = detail_doc;
        }
        return CMAPER_OK;
    }

    next = (cmaper_snapshot_merged_host_t *) realloc(
        *items,
        (*count + 1U) * sizeof(cmaper_snapshot_merged_host_t)
    );
    if (next == NULL) {
        return CMAPER_ERR_OOM;
    }

    *items = next;
    snprintf((*items)[*count].ip, sizeof((*items)[*count].ip), "%s", ip);
    (*items)[*count].discovery_host = discovery_host;
    (*items)[*count].detail_doc = detail_doc;
    *count += 1U;

    return CMAPER_OK;
}

static cmaper_err_t cmaper_snapshot_build_merged_hosts(
    const cmaper_nmap_xml_document_t *discovery_doc,
    const cmaper_snapshot_detail_doc_t *detail_docs,
    size_t detail_doc_count,
    cmaper_snapshot_merged_host_t **out_items,
    size_t *out_count
) {
    cmaper_snapshot_merged_host_t *items = NULL;
    size_t count = 0;
    size_t i;
    cmaper_err_t rc;

    if (discovery_doc == NULL || out_items == NULL || out_count == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    *out_items = NULL;
    *out_count = 0;

    for (i = 0; i < discovery_doc->host_count; ++i) {
        const cmaper_nmap_xml_host_t *host = &discovery_doc->hosts[i];
        const char *ip = cmaper_nmap_host_primary_ip(host);
        const cmaper_snapshot_detail_doc_t *detail_doc;

        if (ip == NULL || ip[0] == '\0') {
            continue;
        }

        detail_doc = cmaper_snapshot_find_detail_doc_for_ip(detail_docs, detail_doc_count, ip);
        rc = cmaper_snapshot_append_or_merge_merged_host(
            &items,
            &count,
            ip,
            host,
            detail_doc
        );
        if (rc != CMAPER_OK) {
            cmaper_snapshot_merged_hosts_dispose(items);
            return rc;
        }
    }

    for (i = 0; i < detail_doc_count; ++i) {
        if (!detail_docs[i].loaded || detail_docs[i].host == NULL || detail_docs[i].ip[0] == '\0') {
            continue;
        }

        rc = cmaper_snapshot_append_or_merge_merged_host(
            &items,
            &count,
            detail_docs[i].ip,
            NULL,
            &detail_docs[i]
        );
        if (rc != CMAPER_OK) {
            cmaper_snapshot_merged_hosts_dispose(items);
            return rc;
        }
    }

    if (count > 1U) {
        qsort(items, count, sizeof(cmaper_snapshot_merged_host_t), cmaper_snapshot_merged_host_compare);
    }

    *out_items = items;
    *out_count = count;
    return CMAPER_OK;
}

cmaper_err_t cmaper_snapshot_write_scan_data(
    sqlite3 *db,
    const cmaper_snapshot_write_request_t *request,
    cmaper_logger_t *logger
) {
    cmaper_nmap_xml_document_t discovery_doc;
    cmaper_nmap_xml_diag_t discovery_diag;
    cmaper_snapshot_detail_doc_t *detail_docs = NULL;
    size_t detail_doc_count = 0;
    cmaper_snapshot_merged_host_t *merged_hosts = NULL;
    size_t merged_host_count = 0;
    sqlite3_int64 session_id = 0;
    size_t i;
    cmaper_err_t rc;

    if (db == NULL || request == NULL || request->session_uid == NULL
        || request->plan == NULL || request->scan_result == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    if (request->scan_result->discovery_xml == NULL || request->scan_result->discovery_xml_size == 0) {
        return CMAPER_ERR_PARSE;
    }

    rc = cmaper_snapshot_get_session_id(db, request->session_uid, &session_id);
    if (rc != CMAPER_OK || session_id <= 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    cmaper_nmap_xml_document_init(&discovery_doc);
    cmaper_nmap_xml_diag_clear(&discovery_diag);
    rc = cmaper_nmap_xml_parse_memory(
        request->scan_result->discovery_xml,
        request->scan_result->discovery_xml_size,
        &discovery_doc,
        &discovery_diag
    );
    if (rc != CMAPER_OK) {
        cmaper_log(
            logger,
            CMAPER_LOG_FAIL,
            "snapshot/write: discovery xml parse failed: %s",
            discovery_diag.message[0] != '\0' ? discovery_diag.message : "parse error"
        );
        cmaper_nmap_xml_document_dispose(&discovery_doc);
        return CMAPER_ERR_PARSE;
    }

    rc = cmaper_snapshot_build_detail_docs(
        request->scan_result,
        &detail_docs,
        &detail_doc_count,
        logger
    );
    if (rc != CMAPER_OK) {
        cmaper_nmap_xml_document_dispose(&discovery_doc);
        return rc;
    }

    rc = cmaper_snapshot_build_merged_hosts(
        &discovery_doc,
        detail_docs,
        detail_doc_count,
        &merged_hosts,
        &merged_host_count
    );
    if (rc != CMAPER_OK) {
        cmaper_snapshot_detail_docs_dispose(detail_docs, detail_doc_count);
        cmaper_nmap_xml_document_dispose(&discovery_doc);
        return rc;
    }

    rc = cmaper_snapshot_exec(db, "BEGIN IMMEDIATE TRANSACTION;");
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    rc = cmaper_snapshot_upsert_session_networks(db, session_id, request->plan->target);
    if (rc != CMAPER_OK) {
        goto rollback;
    }

    for (i = 0; i < merged_host_count; ++i) {
        rc = cmaper_snapshot_persist_merged_host(db, session_id, &merged_hosts[i], logger);
        if (rc != CMAPER_OK) {
            goto rollback;
        }
    }

    rc = cmaper_snapshot_exec(db, "COMMIT;");
    if (rc != CMAPER_OK) {
        goto rollback;
    }

    cmaper_log(
        logger,
        CMAPER_LOG_OK,
        "snapshot/write: persisted %zu merged host observations",
        merged_host_count
    );

    rc = CMAPER_OK;
    goto cleanup;

rollback:
    sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);

cleanup:
    cmaper_snapshot_merged_hosts_dispose(merged_hosts);
    cmaper_snapshot_detail_docs_dispose(detail_docs, detail_doc_count);
    cmaper_nmap_xml_document_dispose(&discovery_doc);
    return rc;
}
