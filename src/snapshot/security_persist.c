#include "cmaper/snapshot/security.h"

#include <stdio.h>
#include <string.h>

#include "cmaper/snapshot/internal/sqlite_internal.h"

static cmaper_err_t cmaper_snapshot_security_bind_optional_int64(
    sqlite3_stmt *stmt,
    int index,
    sqlite3_int64 value
) {
    int rc;

    if (stmt == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    if (value > 0) {
        rc = sqlite3_bind_int64(stmt, index, value);
    } else {
        rc = sqlite3_bind_null(stmt, index);
    }
    if (rc != SQLITE_OK) {
        return CMAPER_ERR_IO;
    }

    return CMAPER_OK;
}

static void cmaper_snapshot_security_reset(sqlite3_stmt *stmt) {
    if (stmt == NULL) {
        return;
    }

    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
}

static cmaper_err_t cmaper_snapshot_security_lookup_service_observation_id(
    sqlite3_stmt *stmt_lookup,
    sqlite3_int64 host_observation_id,
    const char *protocol,
    int port,
    sqlite3_int64 *out_service_observation_id
) {
    int step_rc;
    cmaper_err_t rc;

    if (stmt_lookup == NULL || protocol == NULL || out_service_observation_id == NULL || port <= 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    *out_service_observation_id = 0;
    cmaper_snapshot_security_reset(stmt_lookup);

    rc = cmaper_snapshot_sqlite_bind_int64(stmt_lookup, 1, host_observation_id);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_snapshot_sqlite_bind_text(stmt_lookup, 2, protocol);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_snapshot_sqlite_bind_int64(stmt_lookup, 3, (sqlite3_int64) port);
    if (rc != CMAPER_OK) {
        return rc;
    }

    step_rc = sqlite3_step(stmt_lookup);
    if (step_rc == SQLITE_ROW) {
        *out_service_observation_id = sqlite3_column_int64(stmt_lookup, 0);
        return CMAPER_OK;
    }
    if (step_rc == SQLITE_DONE) {
        return CMAPER_OK;
    }

    return CMAPER_ERR_IO;
}

static cmaper_err_t cmaper_snapshot_security_insert_fingerprint(
    sqlite3_stmt *stmt_insert,
    sqlite3_int64 host_observation_id,
    sqlite3_int64 service_observation_id,
    const char *fingerprint
) {
    cmaper_err_t rc;

    if (stmt_insert == NULL || fingerprint == NULL || fingerprint[0] == '\0') {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    cmaper_snapshot_security_reset(stmt_insert);

    rc = cmaper_snapshot_sqlite_bind_int64(stmt_insert, 1, host_observation_id);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_snapshot_security_bind_optional_int64(stmt_insert, 2, service_observation_id);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_snapshot_sqlite_bind_text(stmt_insert, 3, fingerprint);
    if (rc != CMAPER_OK) {
        return rc;
    }

    return cmaper_snapshot_sqlite_step_done(stmt_insert);
}

static cmaper_err_t cmaper_snapshot_security_insert_finding(
    sqlite3_stmt *stmt_insert,
    sqlite3_int64 host_observation_id,
    sqlite3_int64 service_observation_id,
    const cmaper_security_finding_t *finding
) {
    cmaper_err_t rc;

    if (stmt_insert == NULL || finding == NULL || finding->key[0] == '\0') {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    cmaper_snapshot_security_reset(stmt_insert);

    rc = cmaper_snapshot_sqlite_bind_int64(stmt_insert, 1, host_observation_id);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_snapshot_security_bind_optional_int64(stmt_insert, 2, service_observation_id);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_snapshot_sqlite_bind_text(stmt_insert, 3, finding->key);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_snapshot_sqlite_bind_text(stmt_insert, 4, cmaper_security_severity_name(finding->severity));
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_snapshot_sqlite_bind_text(stmt_insert, 5, cmaper_security_finding_state_name(finding->state));
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_snapshot_sqlite_bind_text_or_null(stmt_insert, 6, finding->title);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_snapshot_sqlite_bind_text_or_null(stmt_insert, 7, finding->detail);
    if (rc != CMAPER_OK) {
        return rc;
    }

    return cmaper_snapshot_sqlite_step_done(stmt_insert);
}

static cmaper_err_t cmaper_snapshot_security_insert_surface(
    sqlite3_stmt *stmt_insert,
    sqlite3_int64 host_observation_id,
    sqlite3_int64 service_observation_id,
    const cmaper_security_management_surface_t *surface
) {
    cmaper_err_t rc;

    if (stmt_insert == NULL || surface == NULL || surface->type[0] == '\0') {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    cmaper_snapshot_security_reset(stmt_insert);

    rc = cmaper_snapshot_sqlite_bind_int64(stmt_insert, 1, host_observation_id);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_snapshot_security_bind_optional_int64(stmt_insert, 2, service_observation_id);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_snapshot_sqlite_bind_text(stmt_insert, 3, surface->type);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_snapshot_sqlite_bind_text_or_null(stmt_insert, 4, surface->detail);
    if (rc != CMAPER_OK) {
        return rc;
    }

    return cmaper_snapshot_sqlite_step_done(stmt_insert);
}

cmaper_err_t cmaper_snapshot_security_persist_host_artifacts(
    sqlite3 *db,
    sqlite3_int64 host_observation_id,
    const cmaper_security_host_artifacts_t *artifacts,
    cmaper_logger_t *logger
) {
    static const char *SQL_LOOKUP_SERVICE =
        "SELECT so.id "
        "FROM service_observations so "
        "JOIN ports p ON p.id=so.port_id "
        "WHERE so.host_observation_id=? AND p.protocol=? AND p.port_number=? "
        "LIMIT 1;";
    static const char *SQL_TLS =
        "INSERT INTO tls_fingerprints(host_observation_id, service_observation_id, fingerprint) "
        "VALUES(?, ?, ?);";
    static const char *SQL_SSH =
        "INSERT INTO ssh_fingerprints(host_observation_id, service_observation_id, fingerprint) "
        "VALUES(?, ?, ?);";
    static const char *SQL_HTTP =
        "INSERT INTO http_fingerprints(host_observation_id, service_observation_id, fingerprint) "
        "VALUES(?, ?, ?);";
    static const char *SQL_SMB =
        "INSERT INTO smb_fingerprints(host_observation_id, service_observation_id, fingerprint) "
        "VALUES(?, ?, ?);";
    static const char *SQL_FINDING =
        "INSERT INTO vulnerability_findings("
        "  host_observation_id, service_observation_id, finding_key, severity, state, title, detail"
        ") VALUES(?, ?, ?, ?, ?, ?, ?);";
    static const char *SQL_SURFACE =
        "INSERT INTO management_surfaces("
        "  host_observation_id, service_observation_id, surface_type, detail"
        ") VALUES(?, ?, ?, ?);";

    sqlite3_stmt *stmt_lookup_service = NULL;
    sqlite3_stmt *stmt_tls = NULL;
    sqlite3_stmt *stmt_ssh = NULL;
    sqlite3_stmt *stmt_http = NULL;
    sqlite3_stmt *stmt_smb = NULL;
    sqlite3_stmt *stmt_finding = NULL;
    sqlite3_stmt *stmt_surface = NULL;
    cmaper_err_t rc;
    size_t i;

    if (db == NULL || artifacts == NULL || host_observation_id <= 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = cmaper_snapshot_sqlite_prepare(db, SQL_LOOKUP_SERVICE, &stmt_lookup_service);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_prepare(db, SQL_TLS, &stmt_tls);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_prepare(db, SQL_SSH, &stmt_ssh);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_prepare(db, SQL_HTTP, &stmt_http);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_prepare(db, SQL_SMB, &stmt_smb);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_prepare(db, SQL_FINDING, &stmt_finding);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_snapshot_sqlite_prepare(db, SQL_SURFACE, &stmt_surface);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    for (i = 0; i < artifacts->fingerprint_count; ++i) {
        const cmaper_security_fingerprint_observation_t *observation = &artifacts->fingerprints[i];
        sqlite3_int64 service_observation_id = 0;
        sqlite3_stmt *stmt_insert = NULL;

        if (observation->has_service_context && observation->port > 0 && observation->protocol[0] != '\0') {
            rc = cmaper_snapshot_security_lookup_service_observation_id(
                stmt_lookup_service,
                host_observation_id,
                observation->protocol,
                observation->port,
                &service_observation_id
            );
            if (rc != CMAPER_OK) {
                goto cleanup;
            }
        }

        switch (observation->fingerprint.kind) {
        case CMAPER_SECURITY_FP_TLS:
            stmt_insert = stmt_tls;
            break;
        case CMAPER_SECURITY_FP_SSH:
            stmt_insert = stmt_ssh;
            break;
        case CMAPER_SECURITY_FP_HTTP:
            stmt_insert = stmt_http;
            break;
        case CMAPER_SECURITY_FP_SMB:
            stmt_insert = stmt_smb;
            break;
        }

        rc = cmaper_snapshot_security_insert_fingerprint(
            stmt_insert,
            host_observation_id,
            service_observation_id,
            observation->fingerprint.value
        );
        if (rc != CMAPER_OK) {
            goto cleanup;
        }
    }

    for (i = 0; i < artifacts->finding_count; ++i) {
        const cmaper_security_finding_observation_t *observation = &artifacts->findings[i];
        sqlite3_int64 service_observation_id = 0;

        if (observation->has_service_context && observation->port > 0 && observation->protocol[0] != '\0') {
            rc = cmaper_snapshot_security_lookup_service_observation_id(
                stmt_lookup_service,
                host_observation_id,
                observation->protocol,
                observation->port,
                &service_observation_id
            );
            if (rc != CMAPER_OK) {
                goto cleanup;
            }
        }

        rc = cmaper_snapshot_security_insert_finding(
            stmt_finding,
            host_observation_id,
            service_observation_id,
            &observation->finding
        );
        if (rc != CMAPER_OK) {
            goto cleanup;
        }
    }

    for (i = 0; i < artifacts->surface_count; ++i) {
        const cmaper_security_surface_observation_t *observation = &artifacts->surfaces[i];
        sqlite3_int64 service_observation_id = 0;

        if (observation->has_service_context && observation->port > 0 && observation->protocol[0] != '\0') {
            rc = cmaper_snapshot_security_lookup_service_observation_id(
                stmt_lookup_service,
                host_observation_id,
                observation->protocol,
                observation->port,
                &service_observation_id
            );
            if (rc != CMAPER_OK) {
                goto cleanup;
            }
        }

        rc = cmaper_snapshot_security_insert_surface(
            stmt_surface,
            host_observation_id,
            service_observation_id,
            &observation->surface
        );
        if (rc != CMAPER_OK) {
            goto cleanup;
        }
    }

    if (logger != NULL) {
        cmaper_log(
            logger,
            CMAPER_LOG_INFO,
            "snapshot/security: host=%lld fingerprints=%zu findings=%zu surfaces=%zu",
            (long long) host_observation_id,
            artifacts->fingerprint_count,
            artifacts->finding_count,
            artifacts->surface_count
        );
    }

    rc = CMAPER_OK;

cleanup:
    cmaper_snapshot_sqlite_finalize(&stmt_lookup_service);
    cmaper_snapshot_sqlite_finalize(&stmt_tls);
    cmaper_snapshot_sqlite_finalize(&stmt_ssh);
    cmaper_snapshot_sqlite_finalize(&stmt_http);
    cmaper_snapshot_sqlite_finalize(&stmt_smb);
    cmaper_snapshot_sqlite_finalize(&stmt_finding);
    cmaper_snapshot_sqlite_finalize(&stmt_surface);
    return rc;
}
