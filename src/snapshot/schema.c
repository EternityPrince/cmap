#include "cmaper/snapshot/schema.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

typedef struct {
    int version;
    const char *const *statements;
    size_t statement_count;
} cmaper_snapshot_migration_t;

static const char *CMAPER_SNAPSHOT_SCHEMA_V1[] = {
    "CREATE TABLE IF NOT EXISTS scan_sessions ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  session_uid TEXT NOT NULL UNIQUE,"
    "  status TEXT NOT NULL CHECK (status IN ('running','completed','failed')),"
    "  target TEXT NOT NULL,"
    "  profile TEXT NOT NULL,"
    "  exact_ports TEXT,"
    "  no_ping INTEGER NOT NULL DEFAULT 0 CHECK (no_ping IN (0,1)),"
    "  timing_template INTEGER NOT NULL DEFAULT 3,"
    "  detail_workers INTEGER NOT NULL DEFAULT 16,"
    "  service_detection INTEGER NOT NULL DEFAULT 0 CHECK (service_detection IN (0,1)),"
    "  os_detection INTEGER NOT NULL DEFAULT 0 CHECK (os_detection IN (0,1)),"
    "  sudo INTEGER NOT NULL DEFAULT 0 CHECK (sudo IN (0,1)),"
    "  spoof_mac_mode TEXT NOT NULL DEFAULT 'off'"
    "    CHECK (spoof_mac_mode IN ('off','random','custom')),"
    "  spoof_mac_value TEXT,"
    "  traceroute INTEGER NOT NULL DEFAULT 0 CHECK (traceroute IN (0,1)),"
    "  udp_enrichment INTEGER NOT NULL DEFAULT 0 CHECK (udp_enrichment IN (0,1)),"
    "  discovery_xml_path TEXT,"
    "  detail_targets_total INTEGER NOT NULL DEFAULT 0,"
    "  detail_hosts_success INTEGER NOT NULL DEFAULT 0,"
    "  detail_hosts_failed INTEGER NOT NULL DEFAULT 0,"
    "  detail_hosts_degraded INTEGER NOT NULL DEFAULT 0,"
    "  error_message TEXT,"
    "  started_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),"
    "  completed_at TEXT,"
    "  failed_at TEXT"
    ");",

    "CREATE TABLE IF NOT EXISTS networks ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  cidr TEXT NOT NULL UNIQUE,"
    "  first_seen_session_id INTEGER REFERENCES scan_sessions(id) ON DELETE SET NULL,"
    "  last_seen_session_id INTEGER REFERENCES scan_sessions(id) ON DELETE SET NULL,"
    "  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))"
    ");",

    "CREATE TABLE IF NOT EXISTS session_networks ("
    "  session_id INTEGER NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,"
    "  network_id INTEGER NOT NULL REFERENCES networks(id) ON DELETE CASCADE,"
    "  PRIMARY KEY (session_id, network_id)"
    ");",

    "CREATE TABLE IF NOT EXISTS devices ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  stable_key TEXT NOT NULL UNIQUE,"
    "  fallback_key TEXT NOT NULL UNIQUE,"
    "  mac_address TEXT,"
    "  mac_vendor TEXT,"
    "  first_seen_session_id INTEGER REFERENCES scan_sessions(id) ON DELETE SET NULL,"
    "  last_seen_session_id INTEGER REFERENCES scan_sessions(id) ON DELETE SET NULL,"
    "  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),"
    "  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))"
    ");",

    "CREATE TABLE IF NOT EXISTS device_ip_addresses ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,"
    "  ip_address TEXT NOT NULL,"
    "  address_type TEXT,"
    "  first_seen_session_id INTEGER REFERENCES scan_sessions(id) ON DELETE SET NULL,"
    "  last_seen_session_id INTEGER REFERENCES scan_sessions(id) ON DELETE SET NULL,"
    "  is_current INTEGER NOT NULL DEFAULT 1 CHECK (is_current IN (0,1)),"
    "  UNIQUE (device_id, ip_address)"
    ");",

    "CREATE TABLE IF NOT EXISTS host_observations ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  session_id INTEGER NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,"
    "  device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,"
    "  primary_ip TEXT NOT NULL,"
    "  primary_ip_type TEXT,"
    "  status TEXT,"
    "  observation_source TEXT NOT NULL DEFAULT 'merged',"
    "  hostname_primary TEXT,"
    "  mac_address TEXT,"
    "  mac_vendor TEXT,"
    "  detail_xml_path TEXT,"
    "  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),"
    "  UNIQUE (session_id, device_id, primary_ip)"
    ");",

    "CREATE TABLE IF NOT EXISTS os_matches ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  host_observation_id INTEGER NOT NULL REFERENCES host_observations(id) ON DELETE CASCADE,"
    "  name TEXT NOT NULL,"
    "  accuracy INTEGER,"
    "  line INTEGER"
    ");",

    "CREATE TABLE IF NOT EXISTS ports ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  protocol TEXT NOT NULL,"
    "  port_number INTEGER NOT NULL,"
    "  UNIQUE (protocol, port_number)"
    ");",

    "CREATE TABLE IF NOT EXISTS service_observations ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  host_observation_id INTEGER NOT NULL REFERENCES host_observations(id) ON DELETE CASCADE,"
    "  port_id INTEGER NOT NULL REFERENCES ports(id),"
    "  state TEXT,"
    "  reason TEXT,"
    "  service_name TEXT,"
    "  service_product TEXT,"
    "  service_version TEXT,"
    "  UNIQUE (host_observation_id, port_id)"
    ");",

    "CREATE TABLE IF NOT EXISTS script_results ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  host_observation_id INTEGER REFERENCES host_observations(id) ON DELETE CASCADE,"
    "  service_observation_id INTEGER REFERENCES service_observations(id) ON DELETE CASCADE,"
    "  script_id TEXT NOT NULL,"
    "  output TEXT,"
    "  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),"
    "  CHECK (host_observation_id IS NOT NULL OR service_observation_id IS NOT NULL)"
    ");",

    "CREATE TABLE IF NOT EXISTS tls_fingerprints ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  host_observation_id INTEGER REFERENCES host_observations(id) ON DELETE CASCADE,"
    "  service_observation_id INTEGER REFERENCES service_observations(id) ON DELETE CASCADE,"
    "  fingerprint TEXT,"
    "  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),"
    "  CHECK (host_observation_id IS NOT NULL OR service_observation_id IS NOT NULL)"
    ");",

    "CREATE TABLE IF NOT EXISTS ssh_fingerprints ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  host_observation_id INTEGER REFERENCES host_observations(id) ON DELETE CASCADE,"
    "  service_observation_id INTEGER REFERENCES service_observations(id) ON DELETE CASCADE,"
    "  fingerprint TEXT,"
    "  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),"
    "  CHECK (host_observation_id IS NOT NULL OR service_observation_id IS NOT NULL)"
    ");",

    "CREATE TABLE IF NOT EXISTS http_fingerprints ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  host_observation_id INTEGER REFERENCES host_observations(id) ON DELETE CASCADE,"
    "  service_observation_id INTEGER REFERENCES service_observations(id) ON DELETE CASCADE,"
    "  fingerprint TEXT,"
    "  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),"
    "  CHECK (host_observation_id IS NOT NULL OR service_observation_id IS NOT NULL)"
    ");",

    "CREATE TABLE IF NOT EXISTS smb_fingerprints ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  host_observation_id INTEGER REFERENCES host_observations(id) ON DELETE CASCADE,"
    "  service_observation_id INTEGER REFERENCES service_observations(id) ON DELETE CASCADE,"
    "  fingerprint TEXT,"
    "  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),"
    "  CHECK (host_observation_id IS NOT NULL OR service_observation_id IS NOT NULL)"
    ");",

    "CREATE TABLE IF NOT EXISTS vulnerability_findings ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  host_observation_id INTEGER REFERENCES host_observations(id) ON DELETE CASCADE,"
    "  service_observation_id INTEGER REFERENCES service_observations(id) ON DELETE CASCADE,"
    "  finding_key TEXT,"
    "  severity TEXT,"
    "  title TEXT,"
    "  detail TEXT,"
    "  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),"
    "  CHECK (host_observation_id IS NOT NULL OR service_observation_id IS NOT NULL)"
    ");",

    "CREATE TABLE IF NOT EXISTS management_surfaces ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  host_observation_id INTEGER REFERENCES host_observations(id) ON DELETE CASCADE,"
    "  service_observation_id INTEGER REFERENCES service_observations(id) ON DELETE CASCADE,"
    "  surface_type TEXT NOT NULL,"
    "  detail TEXT,"
    "  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),"
    "  CHECK (host_observation_id IS NOT NULL OR service_observation_id IS NOT NULL)"
    ");",

    "CREATE TABLE IF NOT EXISTS traces ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  host_observation_id INTEGER NOT NULL REFERENCES host_observations(id) ON DELETE CASCADE,"
    "  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))"
    ");",

    "CREATE TABLE IF NOT EXISTS trace_hops ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  trace_id INTEGER NOT NULL REFERENCES traces(id) ON DELETE CASCADE,"
    "  hop_index INTEGER NOT NULL,"
    "  ttl INTEGER,"
    "  ipaddr TEXT,"
    "  rtt TEXT,"
    "  host TEXT,"
    "  UNIQUE (trace_id, hop_index)"
    ");",

    "CREATE INDEX IF NOT EXISTS idx_scan_sessions_started_at"
    " ON scan_sessions(started_at);",
    "CREATE INDEX IF NOT EXISTS idx_scan_sessions_status"
    " ON scan_sessions(status);",

    "CREATE INDEX IF NOT EXISTS idx_devices_mac_address"
    " ON devices(mac_address);",
    "CREATE INDEX IF NOT EXISTS idx_device_ip_addresses_ip_current"
    " ON device_ip_addresses(ip_address, is_current);",
    "CREATE INDEX IF NOT EXISTS idx_device_ip_addresses_device_id"
    " ON device_ip_addresses(device_id);",

    "CREATE INDEX IF NOT EXISTS idx_host_observations_session_id"
    " ON host_observations(session_id);",
    "CREATE INDEX IF NOT EXISTS idx_host_observations_device_id"
    " ON host_observations(device_id);",

    "CREATE INDEX IF NOT EXISTS idx_os_matches_host_observation_id"
    " ON os_matches(host_observation_id);",
    "CREATE INDEX IF NOT EXISTS idx_service_observations_host_observation_id"
    " ON service_observations(host_observation_id);",
    "CREATE INDEX IF NOT EXISTS idx_script_results_host_observation_id"
    " ON script_results(host_observation_id);",
    "CREATE INDEX IF NOT EXISTS idx_script_results_service_observation_id"
    " ON script_results(service_observation_id);",

    "CREATE INDEX IF NOT EXISTS idx_traces_host_observation_id"
    " ON traces(host_observation_id);",
    "CREATE INDEX IF NOT EXISTS idx_trace_hops_trace_id"
    " ON trace_hops(trace_id);"
};

static const char *CMAPER_SNAPSHOT_SCHEMA_V2[] = {
    "ALTER TABLE vulnerability_findings ADD COLUMN state TEXT;",
    "CREATE INDEX IF NOT EXISTS idx_vulnerability_findings_host_observation_id"
    " ON vulnerability_findings(host_observation_id);",
    "CREATE INDEX IF NOT EXISTS idx_vulnerability_findings_service_observation_id"
    " ON vulnerability_findings(service_observation_id);",
    "CREATE INDEX IF NOT EXISTS idx_vulnerability_findings_key"
    " ON vulnerability_findings(finding_key);",
    "CREATE INDEX IF NOT EXISTS idx_vulnerability_findings_severity_state"
    " ON vulnerability_findings(severity, state);",
    "CREATE INDEX IF NOT EXISTS idx_management_surfaces_host_observation_id"
    " ON management_surfaces(host_observation_id);",
    "CREATE INDEX IF NOT EXISTS idx_management_surfaces_service_observation_id"
    " ON management_surfaces(service_observation_id);",
    "CREATE INDEX IF NOT EXISTS idx_tls_fingerprints_host_observation_id"
    " ON tls_fingerprints(host_observation_id);",
    "CREATE INDEX IF NOT EXISTS idx_ssh_fingerprints_host_observation_id"
    " ON ssh_fingerprints(host_observation_id);",
    "CREATE INDEX IF NOT EXISTS idx_http_fingerprints_host_observation_id"
    " ON http_fingerprints(host_observation_id);",
    "CREATE INDEX IF NOT EXISTS idx_smb_fingerprints_host_observation_id"
    " ON smb_fingerprints(host_observation_id);"
};

static const cmaper_snapshot_migration_t CMAPER_SNAPSHOT_MIGRATIONS[] = {
    {
        1,
        CMAPER_SNAPSHOT_SCHEMA_V1,
        sizeof(CMAPER_SNAPSHOT_SCHEMA_V1) / sizeof(CMAPER_SNAPSHOT_SCHEMA_V1[0])
    },
    {
        2,
        CMAPER_SNAPSHOT_SCHEMA_V2,
        sizeof(CMAPER_SNAPSHOT_SCHEMA_V2) / sizeof(CMAPER_SNAPSHOT_SCHEMA_V2[0])
    }
};

static void cmaper_snapshot_schema_diag_set_sqlite(
    cmaper_snapshot_schema_diag_t *diag,
    const char *field,
    sqlite3 *db
) {
    const char *message = db != NULL ? sqlite3_errmsg(db) : "sqlite error";
    cmaper_snapshot_schema_diag_setf(diag, field, "%s", message);
}

static cmaper_err_t cmaper_snapshot_schema_get_user_version(sqlite3 *db, int *out_version) {
    sqlite3_stmt *stmt = NULL;
    int rc;

    if (db == NULL || out_version == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    *out_version = 0;
    rc = sqlite3_prepare_v2(db, "PRAGMA user_version;", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return CMAPER_ERR_IO;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *out_version = sqlite3_column_int(stmt, 0);
    } else {
        sqlite3_finalize(stmt);
        return CMAPER_ERR_IO;
    }

    sqlite3_finalize(stmt);
    return CMAPER_OK;
}

static cmaper_err_t cmaper_snapshot_schema_exec(sqlite3 *db, const char *sql) {
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

static cmaper_err_t cmaper_snapshot_schema_apply_migration(
    sqlite3 *db,
    const cmaper_snapshot_migration_t *migration,
    cmaper_snapshot_schema_diag_t *diag
) {
    size_t i;
    char pragma_sql[64];
    cmaper_err_t rc;

    rc = cmaper_snapshot_schema_exec(db, "BEGIN IMMEDIATE TRANSACTION;");
    if (rc != CMAPER_OK) {
        cmaper_snapshot_schema_diag_set_sqlite(diag, "schema", db);
        return rc;
    }

    for (i = 0; i < migration->statement_count; ++i) {
        rc = cmaper_snapshot_schema_exec(db, migration->statements[i]);
        if (rc != CMAPER_OK) {
            cmaper_snapshot_schema_diag_setf(
                diag,
                "schema",
                "migration v%d statement #%zu failed: %s",
                migration->version,
                i + 1U,
                sqlite3_errmsg(db)
            );
            sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
            return rc;
        }
    }

    if (snprintf(pragma_sql, sizeof(pragma_sql), "PRAGMA user_version=%d;", migration->version)
        >= (int) sizeof(pragma_sql)) {
        cmaper_snapshot_schema_diag_setf(diag, "schema", "failed to format user_version pragma");
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        return CMAPER_ERR_INTERNAL;
    }

    rc = cmaper_snapshot_schema_exec(db, pragma_sql);
    if (rc != CMAPER_OK) {
        cmaper_snapshot_schema_diag_set_sqlite(diag, "schema", db);
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        return rc;
    }

    rc = cmaper_snapshot_schema_exec(db, "COMMIT;");
    if (rc != CMAPER_OK) {
        cmaper_snapshot_schema_diag_set_sqlite(diag, "schema", db);
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        return rc;
    }

    return CMAPER_OK;
}

void cmaper_snapshot_schema_diag_clear(cmaper_snapshot_schema_diag_t *diag) {
    if (diag == NULL) {
        return;
    }

    diag->field = NULL;
    diag->message[0] = '\0';
}

void cmaper_snapshot_schema_diag_setf(
    cmaper_snapshot_schema_diag_t *diag,
    const char *field,
    const char *fmt,
    ...
) {
    va_list args;

    cmaper_snapshot_schema_diag_clear(diag);
    if (diag == NULL) {
        return;
    }

    diag->field = field;
    if (fmt == NULL) {
        return;
    }

    va_start(args, fmt);
    vsnprintf(diag->message, sizeof(diag->message), fmt, args);
    va_end(args);
}

int cmaper_snapshot_schema_latest_version(void) {
    const size_t count = sizeof(CMAPER_SNAPSHOT_MIGRATIONS)
        / sizeof(CMAPER_SNAPSHOT_MIGRATIONS[0]);

    if (count == 0) {
        return 0;
    }

    return CMAPER_SNAPSHOT_MIGRATIONS[count - 1U].version;
}

cmaper_err_t cmaper_snapshot_schema_bootstrap(
    sqlite3 *db,
    cmaper_snapshot_schema_diag_t *diag
) {
    const size_t migration_count = sizeof(CMAPER_SNAPSHOT_MIGRATIONS)
        / sizeof(CMAPER_SNAPSHOT_MIGRATIONS[0]);
    int user_version = 0;
    int latest_version = cmaper_snapshot_schema_latest_version();
    size_t i;
    cmaper_err_t rc;

    if (db == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    cmaper_snapshot_schema_diag_clear(diag);

    rc = cmaper_snapshot_schema_get_user_version(db, &user_version);
    if (rc != CMAPER_OK) {
        cmaper_snapshot_schema_diag_set_sqlite(diag, "schema", db);
        return rc;
    }

    if (user_version > latest_version) {
        cmaper_snapshot_schema_diag_setf(
            diag,
            "schema",
            "database schema version %d is newer than supported version %d",
            user_version,
            latest_version
        );
        return CMAPER_ERR_UNIMPLEMENTED;
    }

    for (i = 0; i < migration_count; ++i) {
        const cmaper_snapshot_migration_t *migration = &CMAPER_SNAPSHOT_MIGRATIONS[i];
        if (migration->version <= user_version) {
            continue;
        }

        rc = cmaper_snapshot_schema_apply_migration(db, migration, diag);
        if (rc != CMAPER_OK) {
            return rc;
        }
        user_version = migration->version;
    }

    return CMAPER_OK;
}
