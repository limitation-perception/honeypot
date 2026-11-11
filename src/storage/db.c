#include "storage/db.h"

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

#include "core/log.h"

struct db {
    sqlite3      *conn;
    sqlite3_stmt *insert_event;
    sqlite3_stmt *insert_incident;
    sqlite3_stmt *update_incident;
};

static const char *const schema[] = {
    "PRAGMA foreign_keys = ON",
    "CREATE TABLE IF NOT EXISTS incidents ("
    "  id          INTEGER PRIMARY KEY,"
    "  src_ip      TEXT    NOT NULL,"
    "  first_seen  INTEGER NOT NULL,"
    "  last_seen   INTEGER NOT NULL,"
    "  level       TEXT    NOT NULL,"
    "  event_count INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS events ("
    "  id          INTEGER PRIMARY KEY,"
    "  incident_id INTEGER REFERENCES incidents (id),"
    "  type        TEXT    NOT NULL,"
    "  source      TEXT    NOT NULL,"
    "  timestamp   INTEGER NOT NULL,"
    "  src_ip      TEXT    NOT NULL,"
    "  dst_port    INTEGER NOT NULL,"
    "  session_id  INTEGER NOT NULL,"
    "  username    TEXT    NOT NULL,"
    "  password    TEXT    NOT NULL,"
    "  details     TEXT    NOT NULL)",
    "CREATE INDEX IF NOT EXISTS events_src_ip ON events (src_ip)",
    "CREATE INDEX IF NOT EXISTS events_incident ON events (incident_id)",
};

static const char SQL_INSERT_EVENT[] =
    "INSERT INTO events (incident_id, type, source, timestamp, src_ip, dst_port,"
    " session_id, username, password, details)"
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

static const char SQL_INSERT_INCIDENT[] =
    "INSERT INTO incidents (src_ip, first_seen, last_seen, level, event_count)"
    " VALUES (?, ?, ?, ?, ?)";

static const char SQL_UPDATE_INCIDENT[] =
    "UPDATE incidents SET src_ip = ?, first_seen = ?, last_seen = ?, level = ?,"
    " event_count = ? WHERE id = ?";

static sqlite3_stmt *prepare(sqlite3 *conn, const char *sql)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(conn, sql, -1, &st, NULL) != SQLITE_OK) {
        LOG_ERROR("cannot prepare '%s': %s", sql, sqlite3_errmsg(conn));
        return NULL;
    }
    return st;
}

static int step_done(sqlite3 *conn, sqlite3_stmt *st, int bind_rc)
{
    int rc = bind_rc == SQLITE_OK ? sqlite3_step(st) : bind_rc;
    if (rc != SQLITE_DONE)
        LOG_ERROR("'%s' failed: %s", sqlite3_sql(st), sqlite3_errmsg(conn));
    sqlite3_reset(st);
    sqlite3_clear_bindings(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int exec_sql(sqlite3 *conn, const char *sql)
{
    sqlite3_stmt *st = prepare(conn, sql);
    if (!st)
        return -1;
    int rc = step_done(conn, st, SQLITE_OK);
    sqlite3_finalize(st);
    return rc;
}

static int bind_field(sqlite3_stmt *st, int idx, const char *buf, size_t size)
{
    return sqlite3_bind_text(st, idx, buf, (int)strnlen(buf, size), SQLITE_STATIC);
}

static int bind_name(sqlite3_stmt *st, int idx, const char *name)
{
    return sqlite3_bind_text(st, idx, name, -1, SQLITE_STATIC);
}

struct db *db_open(const char *path)
{
    struct db *db = calloc(1, sizeof *db);
    if (!db) {
        LOG_ERROR("cannot allocate db");
        return NULL;
    }

    if (sqlite3_open_v2(path, &db->conn, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                        NULL) != SQLITE_OK) {
        LOG_ERROR("cannot open database '%s': %s", path,
                  db->conn ? sqlite3_errmsg(db->conn) : "out of memory");
        db_close(db);
        return NULL;
    }

    for (size_t i = 0; i < sizeof schema / sizeof schema[0]; i++) {
        if (exec_sql(db->conn, schema[i]) != 0) {
            LOG_ERROR("cannot create schema in '%s'", path);
            db_close(db);
            return NULL;
        }
    }

    db->insert_event = prepare(db->conn, SQL_INSERT_EVENT);
    db->insert_incident = prepare(db->conn, SQL_INSERT_INCIDENT);
    db->update_incident = prepare(db->conn, SQL_UPDATE_INCIDENT);
    if (!db->insert_event || !db->insert_incident || !db->update_incident) {
        db_close(db);
        return NULL;
    }
    return db;
}

void db_close(struct db *db)
{
    if (!db)
        return;
    sqlite3_finalize(db->insert_event);
    sqlite3_finalize(db->insert_incident);
    sqlite3_finalize(db->update_incident);
    if (sqlite3_close(db->conn) != SQLITE_OK)
        LOG_ERROR("cannot close database: %s", sqlite3_errmsg(db->conn));
    free(db);
}

int db_save_incident(struct db *db, struct incident *inc)
{
    sqlite3_stmt *st = inc->id == 0 ? db->insert_incident : db->update_incident;

    int rc = SQLITE_OK;
    rc |= bind_field(st, 1, inc->src_ip, sizeof inc->src_ip);
    rc |= sqlite3_bind_int64(st, 2, (sqlite3_int64)inc->first_seen);
    rc |= sqlite3_bind_int64(st, 3, (sqlite3_int64)inc->last_seen);
    rc |= bind_name(st, 4, threat_level_name(inc->level));
    rc |= sqlite3_bind_int(st, 5, inc->event_count);
    if (inc->id != 0)
        rc |= sqlite3_bind_int64(st, 6, inc->id);

    if (step_done(db->conn, st, rc) != 0)
        return -1;

    if (inc->id == 0) {
        inc->id = sqlite3_last_insert_rowid(db->conn);
    } else if (sqlite3_changes(db->conn) != 1) {
        LOG_ERROR("incident %lld does not exist", (long long)inc->id);
        return -1;
    }
    return 0;
}

int db_insert_event(struct db *db, const struct event *ev, int64_t incident_id)
{
    sqlite3_stmt *st = db->insert_event;

    int rc = SQLITE_OK;
    rc |= incident_id > 0 ? sqlite3_bind_int64(st, 1, incident_id)
                          : sqlite3_bind_null(st, 1);
    rc |= bind_name(st, 2, event_type_name(ev->type));
    rc |= bind_name(st, 3, event_source_name(ev->source));
    rc |= sqlite3_bind_int64(st, 4, (sqlite3_int64)ev->timestamp);
    rc |= bind_field(st, 5, ev->src_ip, sizeof ev->src_ip);
    rc |= sqlite3_bind_int(st, 6, ev->dst_port);
    rc |= sqlite3_bind_int64(st, 7, ev->session_id);
    rc |= bind_field(st, 8, ev->username, sizeof ev->username);
    rc |= bind_field(st, 9, ev->password, sizeof ev->password);
    rc |= bind_field(st, 10, ev->details, sizeof ev->details);

    return step_done(db->conn, st, rc);
}
