#include "storage/report.h"

#include <errno.h>
#include <sqlite3.h>
#include <string.h>
#include <time.h>

#include "core/event.h"
#include "core/incident.h"
#include "core/log.h"

#define TOP_LIMIT      10
#define TIMELINE_LIMIT 500

struct report {
    sqlite3 *conn;
    FILE    *out;
    int      failed;
};

static const char STYLE[] =
    "body{font-family:system-ui,sans-serif;margin:0 auto;max-width:1100px;padding:16px;"
    "color:#1f2328;background:#fff}"
    "h1{margin-bottom:4px}h2{margin-top:32px;border-bottom:1px solid #d0d7de;padding-bottom:4px}"
    ".muted{color:#656d76}"
    ".cards{display:flex;flex-wrap:wrap;gap:12px}"
    ".card{border:1px solid #d0d7de;border-radius:8px;padding:12px 16px;min-width:120px}"
    ".card b{display:block;font-size:24px}"
    "table{border-collapse:collapse;width:100%;font-size:14px}"
    "th,td{text-align:left;padding:4px 8px;border-bottom:1px solid #eaeef2;vertical-align:top}"
    "td.mono,td code{font-family:ui-monospace,monospace;word-break:break-all}"
    ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:24px}"
    ".lvl{font-weight:bold;padding:1px 6px;border-radius:4px;color:#fff}"
    ".lvl-HIGH{background:#cf222e}.lvl-MEDIUM{background:#bf8700}.lvl-LOW{background:#0969da}"
    "details{margin:8px 0;border:1px solid #d0d7de;border-radius:8px;padding:8px 12px}"
    "summary{cursor:pointer}";

static void put_escaped(FILE *f, const char *s)
{
    for (; *s; s++) {
        switch (*s) {
        case '&':
            fputs("&amp;", f);
            break;
        case '<':
            fputs("&lt;", f);
            break;
        case '>':
            fputs("&gt;", f);
            break;
        case '"':
            fputs("&quot;", f);
            break;
        case '\'':
            fputs("&#39;", f);
            break;
        default:
            fputc(*s, f);
        }
    }
}

static void put_time(FILE *f, sqlite3_int64 ts)
{
    char buf[32];
    time_t t = (time_t)ts;
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(buf, sizeof buf, "%Y-%m-%d %H:%M:%S", &tm);
    fputs(buf, f);
}

static const char *col_text(sqlite3_stmt *st, int col)
{
    const unsigned char *s = sqlite3_column_text(st, col);
    return s ? (const char *)s : "";
}

static sqlite3_stmt *prepare(struct report *r, const char *sql)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(r->conn, sql, -1, &st, NULL) != SQLITE_OK) {
        LOG_ERROR("cannot prepare '%s': %s", sql, sqlite3_errmsg(r->conn));
        r->failed = 1;
        return NULL;
    }
    return st;
}

static int check_bind(struct report *r, sqlite3_stmt *st, int rc)
{
    if (rc != SQLITE_OK) {
        LOG_ERROR("cannot bind parameters of '%s': %s", sqlite3_sql(st), sqlite3_errmsg(r->conn));
        r->failed = 1;
    }
    return rc == SQLITE_OK ? 0 : -1;
}

static void check_done(struct report *r, sqlite3_stmt *st, int rc)
{
    if (rc != SQLITE_DONE) {
        LOG_ERROR("'%s' failed: %s", sqlite3_sql(st), sqlite3_errmsg(r->conn));
        r->failed = 1;
    }
}

static void write_summary(struct report *r, FILE *summary)
{
    sqlite3_stmt *st = prepare(r,
        "SELECT (SELECT COUNT(*) FROM events),"
        "       (SELECT COUNT(*) FROM incidents),"
        "       (SELECT COUNT(DISTINCT src_ip) FROM events),"
        "       (SELECT COUNT(*) FROM incidents WHERE level = ?1),"
        "       (SELECT COUNT(*) FROM incidents WHERE level = ?2),"
        "       (SELECT COUNT(*) FROM incidents WHERE level = ?3),"
        "       (SELECT MIN(timestamp) FROM events),"
        "       (SELECT MAX(timestamp) FROM events)");
    if (!st)
        return;

    int rc = SQLITE_OK;
    rc |= sqlite3_bind_text(st, 1, threat_level_name(THREAT_HIGH), -1, SQLITE_STATIC);
    rc |= sqlite3_bind_text(st, 2, threat_level_name(THREAT_MEDIUM), -1, SQLITE_STATIC);
    rc |= sqlite3_bind_text(st, 3, threat_level_name(THREAT_LOW), -1, SQLITE_STATIC);
    if (check_bind(r, st, rc) != 0) {
        sqlite3_finalize(st);
        return;
    }

    rc = sqlite3_step(st);
    if (rc != SQLITE_ROW) {
        check_done(r, st, rc);
        sqlite3_finalize(st);
        return;
    }

    long long events = sqlite3_column_int64(st, 0);
    long long incidents = sqlite3_column_int64(st, 1);
    long long ips = sqlite3_column_int64(st, 2);
    long long high = sqlite3_column_int64(st, 3);
    long long medium = sqlite3_column_int64(st, 4);
    long long low = sqlite3_column_int64(st, 5);

    fprintf(r->out,
            "<div class=\"cards\">"
            "<div class=\"card\"><b>%lld</b>events</div>"
            "<div class=\"card\"><b>%lld</b>incidents</div>"
            "<div class=\"card\"><b>%lld</b>unique IPs</div>"
            "<div class=\"card\"><b>%lld</b><span class=\"lvl lvl-HIGH\">HIGH</span></div>"
            "<div class=\"card\"><b>%lld</b><span class=\"lvl lvl-MEDIUM\">MEDIUM</span></div>"
            "<div class=\"card\"><b>%lld</b><span class=\"lvl lvl-LOW\">LOW</span></div>"
            "</div>\n",
            events, incidents, ips, high, medium, low);

    if (events > 0) {
        fputs("<p class=\"muted\">Activity from ", r->out);
        put_time(r->out, sqlite3_column_int64(st, 6));
        fputs(" to ", r->out);
        put_time(r->out, sqlite3_column_int64(st, 7));
        fputs("</p>\n", r->out);
    }

    if (summary)
        fprintf(summary,
                "=== HoneyTrap summary ===\n"
                "events: %lld, unique IPs: %lld\n"
                "incidents: %lld (HIGH %lld, MEDIUM %lld, LOW %lld)\n",
                events, ips, incidents, high, medium, low);

    check_done(r, st, sqlite3_step(st));
    sqlite3_finalize(st);
}

static void write_timeline(struct report *r, sqlite3_stmt *st, sqlite3_int64 incident_id)
{
    int rc = SQLITE_OK;
    rc |= sqlite3_bind_int64(st, 1, incident_id);
    rc |= sqlite3_bind_int(st, 2, TIMELINE_LIMIT);
    if (check_bind(r, st, rc) != 0)
        return;

    fputs("<table><tr><th>Time</th><th>Event</th><th>User</th><th>Password</th>"
          "<th>Details</th></tr>\n", r->out);
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        fputs("<tr><td>", r->out);
        put_time(r->out, sqlite3_column_int64(st, 0));
        fputs("</td><td>", r->out);
        put_escaped(r->out, col_text(st, 1));
        fputs("</td><td class=\"mono\">", r->out);
        put_escaped(r->out, col_text(st, 2));
        fputs("</td><td class=\"mono\">", r->out);
        put_escaped(r->out, col_text(st, 3));
        fputs("</td><td class=\"mono\">", r->out);
        put_escaped(r->out, col_text(st, 4));
        fputs("</td></tr>\n", r->out);
    }
    check_done(r, st, rc);
    fputs("</table>\n", r->out);
    sqlite3_reset(st);
    sqlite3_clear_bindings(st);
}

static void write_incidents(struct report *r)
{
    fputs("<h2>Incidents</h2>\n", r->out);

    sqlite3_stmt *inc = prepare(r,
        "SELECT id, src_ip, level, first_seen, last_seen, event_count FROM incidents"
        " ORDER BY CASE level WHEN ?1 THEN 2 WHEN ?2 THEN 1 ELSE 0 END DESC,"
        " last_seen DESC");
    sqlite3_stmt *events = prepare(r,
        "SELECT timestamp, type, username, password, details FROM events"
        " WHERE incident_id = ?1 ORDER BY timestamp, id LIMIT ?2");
    if (!inc || !events)
        goto out;

    int rc = SQLITE_OK;
    rc |= sqlite3_bind_text(inc, 1, threat_level_name(THREAT_HIGH), -1, SQLITE_STATIC);
    rc |= sqlite3_bind_text(inc, 2, threat_level_name(THREAT_MEDIUM), -1, SQLITE_STATIC);
    if (check_bind(r, inc, rc) != 0)
        goto out;

    int rows = 0;
    while ((rc = sqlite3_step(inc)) == SQLITE_ROW) {
        rows++;
        long long count = sqlite3_column_int64(inc, 5);
        fprintf(r->out, "<details><summary><span class=\"lvl lvl-");
        put_escaped(r->out, col_text(inc, 2));
        fputs("\">", r->out);
        put_escaped(r->out, col_text(inc, 2));
        fprintf(r->out, "</span> #%lld <code>", (long long)sqlite3_column_int64(inc, 0));
        put_escaped(r->out, col_text(inc, 1));
        fputs("</code> &middot; ", r->out);
        put_time(r->out, sqlite3_column_int64(inc, 3));
        fputs(" &rarr; ", r->out);
        put_time(r->out, sqlite3_column_int64(inc, 4));
        fprintf(r->out, " &middot; %lld events</summary>\n", count);
        if (count > TIMELINE_LIMIT)
            fprintf(r->out, "<p class=\"muted\">Showing the first %d events.</p>\n",
                    TIMELINE_LIMIT);
        write_timeline(r, events, sqlite3_column_int64(inc, 0));
        fputs("</details>\n", r->out);
    }
    check_done(r, inc, rc);
    if (rows == 0)
        fputs("<p class=\"muted\">No incidents.</p>\n", r->out);

out:
    sqlite3_finalize(inc);
    sqlite3_finalize(events);
}

static void write_top(struct report *r, const char *title, const char *column,
                      const char *sql, const char *type)
{
    fprintf(r->out, "<section><h2>%s</h2>\n", title);

    sqlite3_stmt *st = prepare(r, sql);
    if (!st) {
        fputs("</section>\n", r->out);
        return;
    }

    int rc = sqlite3_bind_int(st, 1, TOP_LIMIT);
    if (type)
        rc |= sqlite3_bind_text(st, 2, type, -1, SQLITE_STATIC);
    if (check_bind(r, st, rc) != 0) {
        sqlite3_finalize(st);
        fputs("</section>\n", r->out);
        return;
    }

    int rows = 0;
    fprintf(r->out, "<table><tr><th>%s</th><th>Count</th></tr>\n", column);
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        rows++;
        fputs("<tr><td class=\"mono\">", r->out);
        put_escaped(r->out, col_text(st, 0));
        fprintf(r->out, "</td><td>%lld</td></tr>\n", (long long)sqlite3_column_int64(st, 1));
    }
    check_done(r, st, rc);
    fputs("</table>\n", r->out);
    if (rows == 0)
        fputs("<p class=\"muted\">No data.</p>\n", r->out);
    fputs("</section>\n", r->out);
    sqlite3_finalize(st);
}

static void write_tops(struct report *r)
{
    fputs("<div class=\"grid\">\n", r->out);
    write_top(r, "Top passwords", "Password",
              "SELECT password, COUNT(*) AS n FROM events WHERE type = ?2"
              " GROUP BY password ORDER BY n DESC, password LIMIT ?1",
              event_type_name(EV_LOGIN_ATTEMPT));
    write_top(r, "Top usernames", "Username",
              "SELECT username, COUNT(*) AS n FROM events WHERE type = ?2"
              " GROUP BY username ORDER BY n DESC, username LIMIT ?1",
              event_type_name(EV_LOGIN_ATTEMPT));
    write_top(r, "Top commands", "Command",
              "SELECT details, COUNT(*) AS n FROM events WHERE type = ?2"
              " GROUP BY details ORDER BY n DESC, details LIMIT ?1",
              event_type_name(EV_COMMAND));
    write_top(r, "Download attempts", "Command",
              "SELECT details, COUNT(*) AS n FROM events WHERE type = ?2"
              " GROUP BY details ORDER BY n DESC, details LIMIT ?1",
              event_type_name(EV_DOWNLOAD_ATTEMPT));
    write_top(r, "Top IPs", "IP",
              "SELECT src_ip, COUNT(*) AS n FROM events"
              " GROUP BY src_ip ORDER BY n DESC, src_ip LIMIT ?1",
              NULL);
    write_top(r, "Event types", "Type",
              "SELECT type, COUNT(*) AS n FROM events"
              " GROUP BY type ORDER BY n DESC, type LIMIT ?1",
              NULL);
    fputs("</div>\n", r->out);
}

int report_generate(const char *db_path, const char *html_path, FILE *summary)
{
    struct report r = { 0 };

    if (sqlite3_open_v2(db_path, &r.conn, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        LOG_ERROR("cannot open database '%s': %s", db_path,
                  r.conn ? sqlite3_errmsg(r.conn) : "out of memory");
        sqlite3_close(r.conn);
        return -1;
    }

    r.out = fopen(html_path, "w");
    if (!r.out) {
        LOG_ERROR("cannot create report '%s': %s", html_path, strerror(errno));
        sqlite3_close(r.conn);
        return -1;
    }

    fprintf(r.out, "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
                   "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                   "<title>HoneyTrap report</title><style>%s</style></head><body>\n"
                   "<h1>HoneyTrap report</h1>\n<p class=\"muted\">Generated ",
            STYLE);
    put_time(r.out, time(NULL));
    fputs("</p>\n", r.out);

    write_summary(&r, summary);
    write_incidents(&r);
    write_tops(&r);

    fputs("</body></html>\n", r.out);

    if (ferror(r.out)) {
        LOG_ERROR("error writing report '%s'", html_path);
        r.failed = 1;
    }
    if (fclose(r.out) != 0) {
        LOG_ERROR("cannot close report '%s': %s", html_path, strerror(errno));
        r.failed = 1;
    }
    if (sqlite3_close(r.conn) != SQLITE_OK) {
        LOG_ERROR("cannot close database '%s': %s", db_path, sqlite3_errmsg(r.conn));
        r.failed = 1;
    }

    if (r.failed)
        return -1;
    if (summary)
        fprintf(summary, "report: %s\n", html_path);
    return 0;
}
