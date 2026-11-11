#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "unity.h"
#include "storage/db.h"

static char path[] = "/tmp/honeytrap_test_XXXXXX";
static struct db *db;
static sqlite3 *check;

void setUp(void)
{
    strcpy(path, "/tmp/honeytrap_test_XXXXXX");
    int fd = mkstemp(path);
    TEST_ASSERT_TRUE(fd >= 0);
    close(fd);
    db = db_open(path);
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_open(path, &check));
}

void tearDown(void)
{
    db_close(db);
    sqlite3_close(check);
    unlink(path);
}

static long long query_int(const char *sql)
{
    sqlite3_stmt *st;
    TEST_ASSERT_EQUAL_INT_MESSAGE(SQLITE_OK, sqlite3_prepare_v2(check, sql, -1, &st, NULL), sql);
    TEST_ASSERT_EQUAL_INT_MESSAGE(SQLITE_ROW, sqlite3_step(st), sql);
    long long v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

static void query_text(const char *sql, char *out, size_t size)
{
    sqlite3_stmt *st;
    TEST_ASSERT_EQUAL_INT_MESSAGE(SQLITE_OK, sqlite3_prepare_v2(check, sql, -1, &st, NULL), sql);
    TEST_ASSERT_EQUAL_INT_MESSAGE(SQLITE_ROW, sqlite3_step(st), sql);
    const unsigned char *s = sqlite3_column_text(st, 0);
    snprintf(out, size, "%s", s ? (const char *)s : "(null)");
    sqlite3_finalize(st);
}

static struct incident make_incident(void)
{
    struct incident inc = {
        .first_seen = 1000,
        .last_seen = 1005,
        .level = THREAT_LOW,
        .event_count = 1,
    };
    event_set_str(inc.src_ip, sizeof inc.src_ip, "45.1.2.3");
    return inc;
}

static void test_threat_level_name(void)
{
    TEST_ASSERT_EQUAL_STRING("LOW", threat_level_name(THREAT_LOW));
    TEST_ASSERT_EQUAL_STRING("MEDIUM", threat_level_name(THREAT_MEDIUM));
    TEST_ASSERT_EQUAL_STRING("HIGH", threat_level_name(THREAT_HIGH));
    TEST_ASSERT_EQUAL_STRING("UNKNOWN", threat_level_name(THREAT_LEVEL_COUNT));
}

static void test_open_bad_path(void)
{
    TEST_ASSERT_NULL(db_open("/nonexistent_dir/honeytrap.db"));
}

static void test_insert_incident_sets_id(void)
{
    struct incident inc = make_incident();
    TEST_ASSERT_EQUAL_INT(0, db_save_incident(db, &inc));
    TEST_ASSERT_TRUE(inc.id > 0);

    char buf[64];
    query_text("SELECT src_ip FROM incidents", buf, sizeof buf);
    TEST_ASSERT_EQUAL_STRING("45.1.2.3", buf);
    query_text("SELECT level FROM incidents", buf, sizeof buf);
    TEST_ASSERT_EQUAL_STRING("LOW", buf);
    TEST_ASSERT_EQUAL_INT64(1000, query_int("SELECT first_seen FROM incidents"));
}

static void test_update_incident(void)
{
    struct incident inc = make_incident();
    TEST_ASSERT_EQUAL_INT(0, db_save_incident(db, &inc));
    int64_t id = inc.id;

    inc.level = THREAT_HIGH;
    inc.event_count = 7;
    inc.last_seen = 2000;
    TEST_ASSERT_EQUAL_INT(0, db_save_incident(db, &inc));
    TEST_ASSERT_EQUAL_INT64(id, inc.id);

    char buf[64];
    query_text("SELECT level FROM incidents", buf, sizeof buf);
    TEST_ASSERT_EQUAL_STRING("HIGH", buf);
    TEST_ASSERT_EQUAL_INT64(1, query_int("SELECT COUNT(*) FROM incidents"));
    TEST_ASSERT_EQUAL_INT64(7, query_int("SELECT event_count FROM incidents"));
    TEST_ASSERT_EQUAL_INT64(2000, query_int("SELECT last_seen FROM incidents"));
}

static void test_update_missing_incident_fails(void)
{
    struct incident inc = make_incident();
    inc.id = 42;
    TEST_ASSERT_EQUAL_INT(-1, db_save_incident(db, &inc));
}

static void test_insert_event_fields(void)
{
    struct incident inc = make_incident();
    TEST_ASSERT_EQUAL_INT(0, db_save_incident(db, &inc));

    struct event ev;
    event_init(&ev, EV_LOGIN_ATTEMPT, EV_SOURCE_HONEYPOT, "45.1.2.3");
    ev.timestamp = 1234;
    ev.dst_port = 2222;
    ev.session_id = 9;
    event_set_str(ev.username, sizeof ev.username, "root");
    event_set_str(ev.password, sizeof ev.password, "123456");
    TEST_ASSERT_EQUAL_INT(0, db_insert_event(db, &ev, inc.id));

    char buf[64];
    query_text("SELECT type FROM events", buf, sizeof buf);
    TEST_ASSERT_EQUAL_STRING("LOGIN_ATTEMPT", buf);
    query_text("SELECT source FROM events", buf, sizeof buf);
    TEST_ASSERT_EQUAL_STRING("honeypot", buf);
    query_text("SELECT username || ':' || password FROM events", buf, sizeof buf);
    TEST_ASSERT_EQUAL_STRING("root:123456", buf);
    TEST_ASSERT_EQUAL_INT64(inc.id, query_int("SELECT incident_id FROM events"));
    TEST_ASSERT_EQUAL_INT64(1234, query_int("SELECT timestamp FROM events"));
    TEST_ASSERT_EQUAL_INT64(2222, query_int("SELECT dst_port FROM events"));
    TEST_ASSERT_EQUAL_INT64(9, query_int("SELECT session_id FROM events"));
}

static void test_event_without_incident(void)
{
    struct event ev;
    event_init(&ev, EV_PORT_SCAN, EV_SOURCE_IDS, "10.0.0.1");
    TEST_ASSERT_EQUAL_INT(0, db_insert_event(db, &ev, 0));
    TEST_ASSERT_EQUAL_INT64(1, query_int("SELECT COUNT(*) FROM events WHERE incident_id IS NULL"));
}

static void test_event_with_missing_incident_fails(void)
{
    struct event ev;
    event_init(&ev, EV_PORT_SCAN, EV_SOURCE_IDS, "10.0.0.1");
    TEST_ASSERT_EQUAL_INT(-1, db_insert_event(db, &ev, 999));
    TEST_ASSERT_EQUAL_INT64(0, query_int("SELECT COUNT(*) FROM events"));
}

static void test_sql_injection_stored_as_text(void)
{
    const char *evil = "'); DROP TABLE events; --";
    struct event ev;
    event_init(&ev, EV_LOGIN_ATTEMPT, EV_SOURCE_HONEYPOT, "6.6.6.6");
    event_set_str(ev.password, sizeof ev.password, evil);
    TEST_ASSERT_EQUAL_INT(0, db_insert_event(db, &ev, 0));

    char buf[64];
    query_text("SELECT password FROM events", buf, sizeof buf);
    TEST_ASSERT_EQUAL_STRING(evil, buf);
    TEST_ASSERT_EQUAL_INT64(1, query_int("SELECT COUNT(*) FROM events"));
}

static void test_unterminated_field_is_bounded(void)
{
    struct event ev;
    event_init(&ev, EV_COMMAND, EV_SOURCE_HONEYPOT, "1.1.1.1");
    memset(ev.username, 'A', sizeof ev.username);
    TEST_ASSERT_EQUAL_INT(0, db_insert_event(db, &ev, 0));
    TEST_ASSERT_EQUAL_INT64(EV_USER_LEN, query_int("SELECT length(username) FROM events"));
}

static void test_reopen_keeps_data(void)
{
    struct incident inc = make_incident();
    TEST_ASSERT_EQUAL_INT(0, db_save_incident(db, &inc));
    db_close(db);

    db = db_open(path);
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_EQUAL_INT64(1, query_int("SELECT COUNT(*) FROM incidents"));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_threat_level_name);
    RUN_TEST(test_open_bad_path);
    RUN_TEST(test_insert_incident_sets_id);
    RUN_TEST(test_update_incident);
    RUN_TEST(test_update_missing_incident_fails);
    RUN_TEST(test_insert_event_fields);
    RUN_TEST(test_event_without_incident);
    RUN_TEST(test_event_with_missing_incident_fails);
    RUN_TEST(test_sql_injection_stored_as_text);
    RUN_TEST(test_unterminated_field_is_bounded);
    RUN_TEST(test_reopen_keeps_data);
    return UNITY_END();
}
