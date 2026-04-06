#include "cmaper/history/internal/query_internal.h"

#include <stdlib.h>

cmaper_err_t cmaper_history_load_ports(
    sqlite3 *db,
    sqlite3_int64 host_observation_id,
    cmaper_history_host_snapshot_t *snapshot
) {
    static const char *SQL =
        "SELECT p.protocol, p.port_number "
        "FROM service_observations so "
        "JOIN ports p ON p.id=so.port_id "
        "WHERE so.host_observation_id=? AND so.state='open' "
        "ORDER BY p.protocol ASC, p.port_number ASC;";
    sqlite3_stmt *stmt = NULL;
    cmaper_history_buffer_t rows;
    cmaper_err_t rc;
    int step_rc;

    if (db == NULL || snapshot == NULL || host_observation_id <= 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = cmaper_history_buffer_init(&rows, sizeof(cmaper_history_port_signal_t));
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_history_prepare(db, SQL, &stmt);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_history_bind_int64(stmt, 1, host_observation_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        cmaper_history_port_signal_t *row =
            (cmaper_history_port_signal_t *) cmaper_history_buffer_push(&rows);
        if (row == NULL) {
            rc = CMAPER_ERR_OOM;
            goto cleanup;
        }
        cmaper_history_copy_column_text(row->protocol, sizeof(row->protocol), stmt, 0);
        row->port = sqlite3_column_int(stmt, 1);
    }
    if (step_rc != SQLITE_DONE) {
        rc = CMAPER_ERR_IO;
        goto cleanup;
    }

    snapshot->ports = (cmaper_history_port_signal_t *) rows.items;
    snapshot->port_count = rows.count;
    rows.items = NULL;
    rc = CMAPER_OK;

cleanup:
    cmaper_history_finalize(&stmt);
    cmaper_history_buffer_dispose(&rows);
    return rc;
}

cmaper_err_t cmaper_history_load_fingerprints(
    sqlite3 *db,
    sqlite3_int64 host_observation_id,
    cmaper_history_host_snapshot_t *snapshot
) {
    static const char *SQL =
        "SELECT x.kind, x.fingerprint, COALESCE(x.protocol,''), COALESCE(x.port_number,0) "
        "FROM ("
        "  SELECT 'tls' AS kind, tf.fingerprint AS fingerprint, p.protocol AS protocol, p.port_number AS port_number "
        "  FROM tls_fingerprints tf "
        "  LEFT JOIN service_observations so ON so.id=tf.service_observation_id "
        "  LEFT JOIN ports p ON p.id=so.port_id "
        "  WHERE tf.host_observation_id=?1 "
        "  UNION ALL "
        "  SELECT 'ssh', sf.fingerprint, p.protocol, p.port_number "
        "  FROM ssh_fingerprints sf "
        "  LEFT JOIN service_observations so ON so.id=sf.service_observation_id "
        "  LEFT JOIN ports p ON p.id=so.port_id "
        "  WHERE sf.host_observation_id=?1 "
        "  UNION ALL "
        "  SELECT 'http', hf.fingerprint, p.protocol, p.port_number "
        "  FROM http_fingerprints hf "
        "  LEFT JOIN service_observations so ON so.id=hf.service_observation_id "
        "  LEFT JOIN ports p ON p.id=so.port_id "
        "  WHERE hf.host_observation_id=?1 "
        "  UNION ALL "
        "  SELECT 'smb', bf.fingerprint, p.protocol, p.port_number "
        "  FROM smb_fingerprints bf "
        "  LEFT JOIN service_observations so ON so.id=bf.service_observation_id "
        "  LEFT JOIN ports p ON p.id=so.port_id "
        "  WHERE bf.host_observation_id=?1 "
        ") AS x "
        "WHERE x.fingerprint IS NOT NULL AND x.fingerprint<>'' "
        "ORDER BY x.kind ASC, x.protocol ASC, x.port_number ASC, x.fingerprint ASC;";
    sqlite3_stmt *stmt = NULL;
    cmaper_history_buffer_t rows;
    cmaper_err_t rc;
    int step_rc;

    if (db == NULL || snapshot == NULL || host_observation_id <= 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = cmaper_history_buffer_init(&rows, sizeof(cmaper_history_fingerprint_signal_t));
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_history_prepare(db, SQL, &stmt);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_history_bind_int64(stmt, 1, host_observation_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        cmaper_history_fingerprint_signal_t *row =
            (cmaper_history_fingerprint_signal_t *) cmaper_history_buffer_push(&rows);
        if (row == NULL) {
            rc = CMAPER_ERR_OOM;
            goto cleanup;
        }
        cmaper_history_copy_column_text(row->kind, sizeof(row->kind), stmt, 0);
        cmaper_history_copy_column_text(row->value, sizeof(row->value), stmt, 1);
        cmaper_history_copy_column_text(row->protocol, sizeof(row->protocol), stmt, 2);
        row->port = sqlite3_column_int(stmt, 3);
        row->has_service_context = row->port > 0 && row->protocol[0] != '\0';
    }
    if (step_rc != SQLITE_DONE) {
        rc = CMAPER_ERR_IO;
        goto cleanup;
    }

    snapshot->fingerprints = (cmaper_history_fingerprint_signal_t *) rows.items;
    snapshot->fingerprint_count = rows.count;
    rows.items = NULL;
    rc = CMAPER_OK;

cleanup:
    cmaper_history_finalize(&stmt);
    cmaper_history_buffer_dispose(&rows);
    return rc;
}

cmaper_err_t cmaper_history_load_script_results(
    sqlite3 *db,
    sqlite3_int64 host_observation_id,
    cmaper_history_host_snapshot_t *snapshot
) {
    static const char *SQL =
        "SELECT COALESCE(sr.script_id,''), COALESCE(sr.output,''), "
        "       COALESCE(p.protocol,''), COALESCE(p.port_number,0) "
        "FROM script_results sr "
        "LEFT JOIN service_observations so ON so.id=sr.service_observation_id "
        "LEFT JOIN ports p ON p.id=so.port_id "
        "WHERE sr.host_observation_id=? "
        "ORDER BY sr.script_id ASC, p.protocol ASC, p.port_number ASC, sr.id ASC;";
    sqlite3_stmt *stmt = NULL;
    cmaper_history_buffer_t rows;
    cmaper_err_t rc;
    int step_rc;

    if (db == NULL || snapshot == NULL || host_observation_id <= 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = cmaper_history_buffer_init(&rows, sizeof(cmaper_history_script_result_signal_t));
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_history_prepare(db, SQL, &stmt);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_history_bind_int64(stmt, 1, host_observation_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        cmaper_history_script_result_signal_t *row =
            (cmaper_history_script_result_signal_t *) cmaper_history_buffer_push(&rows);
        if (row == NULL) {
            rc = CMAPER_ERR_OOM;
            goto cleanup;
        }
        cmaper_history_copy_column_text(row->script_id, sizeof(row->script_id), stmt, 0);
        cmaper_history_copy_column_text(row->output, sizeof(row->output), stmt, 1);
        cmaper_history_copy_column_text(row->protocol, sizeof(row->protocol), stmt, 2);
        row->port = sqlite3_column_int(stmt, 3);
        row->has_service_context = row->port > 0 && row->protocol[0] != '\0';
    }
    if (step_rc != SQLITE_DONE) {
        rc = CMAPER_ERR_IO;
        goto cleanup;
    }

    snapshot->script_results = (cmaper_history_script_result_signal_t *) rows.items;
    snapshot->script_result_count = rows.count;
    rows.items = NULL;
    rc = CMAPER_OK;

cleanup:
    cmaper_history_finalize(&stmt);
    cmaper_history_buffer_dispose(&rows);
    return rc;
}

cmaper_err_t cmaper_history_load_findings(
    sqlite3 *db,
    sqlite3_int64 host_observation_id,
    cmaper_history_host_snapshot_t *snapshot
) {
    static const char *SQL =
        "SELECT COALESCE(vf.finding_key,''), COALESCE(vf.severity,''), COALESCE(vf.state,''), "
        "       COALESCE(vf.title,''), COALESCE(p.protocol,''), COALESCE(p.port_number,0) "
        "FROM vulnerability_findings vf "
        "LEFT JOIN service_observations so ON so.id=vf.service_observation_id "
        "LEFT JOIN ports p ON p.id=so.port_id "
        "WHERE vf.host_observation_id=? "
        "ORDER BY vf.finding_key ASC, p.protocol ASC, p.port_number ASC;";
    sqlite3_stmt *stmt = NULL;
    cmaper_history_buffer_t rows;
    cmaper_err_t rc;
    int step_rc;

    if (db == NULL || snapshot == NULL || host_observation_id <= 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = cmaper_history_buffer_init(&rows, sizeof(cmaper_history_finding_signal_t));
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_history_prepare(db, SQL, &stmt);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_history_bind_int64(stmt, 1, host_observation_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        cmaper_history_finding_signal_t *row =
            (cmaper_history_finding_signal_t *) cmaper_history_buffer_push(&rows);
        if (row == NULL) {
            rc = CMAPER_ERR_OOM;
            goto cleanup;
        }
        cmaper_history_copy_column_text(row->key, sizeof(row->key), stmt, 0);
        cmaper_history_copy_column_text(row->severity, sizeof(row->severity), stmt, 1);
        cmaper_history_copy_column_text(row->state, sizeof(row->state), stmt, 2);
        cmaper_history_copy_column_text(row->title, sizeof(row->title), stmt, 3);
        cmaper_history_copy_column_text(row->protocol, sizeof(row->protocol), stmt, 4);
        row->port = sqlite3_column_int(stmt, 5);
        row->has_service_context = row->port > 0 && row->protocol[0] != '\0';
    }
    if (step_rc != SQLITE_DONE) {
        rc = CMAPER_ERR_IO;
        goto cleanup;
    }

    snapshot->findings = (cmaper_history_finding_signal_t *) rows.items;
    snapshot->finding_count = rows.count;
    rows.items = NULL;
    rc = CMAPER_OK;

cleanup:
    cmaper_history_finalize(&stmt);
    cmaper_history_buffer_dispose(&rows);
    return rc;
}

cmaper_err_t cmaper_history_load_surfaces(
    sqlite3 *db,
    sqlite3_int64 host_observation_id,
    cmaper_history_host_snapshot_t *snapshot
) {
    static const char *SQL =
        "SELECT COALESCE(ms.surface_type,''), COALESCE(ms.detail,''), "
        "       COALESCE(p.protocol,''), COALESCE(p.port_number,0) "
        "FROM management_surfaces ms "
        "LEFT JOIN service_observations so ON so.id=ms.service_observation_id "
        "LEFT JOIN ports p ON p.id=so.port_id "
        "WHERE ms.host_observation_id=? "
        "ORDER BY ms.surface_type ASC, p.protocol ASC, p.port_number ASC;";
    sqlite3_stmt *stmt = NULL;
    cmaper_history_buffer_t rows;
    cmaper_err_t rc;
    int step_rc;

    if (db == NULL || snapshot == NULL || host_observation_id <= 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = cmaper_history_buffer_init(&rows, sizeof(cmaper_history_surface_signal_t));
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_history_prepare(db, SQL, &stmt);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_history_bind_int64(stmt, 1, host_observation_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        cmaper_history_surface_signal_t *row =
            (cmaper_history_surface_signal_t *) cmaper_history_buffer_push(&rows);
        if (row == NULL) {
            rc = CMAPER_ERR_OOM;
            goto cleanup;
        }
        cmaper_history_copy_column_text(row->type, sizeof(row->type), stmt, 0);
        cmaper_history_copy_column_text(row->detail, sizeof(row->detail), stmt, 1);
        cmaper_history_copy_column_text(row->protocol, sizeof(row->protocol), stmt, 2);
        row->port = sqlite3_column_int(stmt, 3);
        row->has_service_context = row->port > 0 && row->protocol[0] != '\0';
    }
    if (step_rc != SQLITE_DONE) {
        rc = CMAPER_ERR_IO;
        goto cleanup;
    }

    snapshot->surfaces = (cmaper_history_surface_signal_t *) rows.items;
    snapshot->surface_count = rows.count;
    rows.items = NULL;
    rc = CMAPER_OK;

cleanup:
    cmaper_history_finalize(&stmt);
    cmaper_history_buffer_dispose(&rows);
    return rc;
}
