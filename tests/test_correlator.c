#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "db_check.h"
#include "core/correlator.h"

#define TIMEOUT 600

static char path[TEMP_DB_PATH_LEN];
static struct db *db;
static sqlite3 *check;
static FILE *out;
static char *out_buf;
static size_t out_len;
static struct correlator *c;

void setUp(void)
{
    make_temp_db_path(path);
    db = db_open(path);
    TEST_ASSERT_NOT_NULL(db);
    TEST_ASSERT_EQUAL_INT(SQLITE_OK, sqlite3_open(path, &check));
    out = open_memstream(&out_buf, &out_len);
    TEST_ASSERT_NOT_NULL(out);
    c = correlator_create(db, out, TIMEOUT);
    TEST_ASSERT_NOT_NULL(c);
}

void tearDown(void)
{
    correlator_destroy(c);
    db_close(db);
    sqlite3_close(check);
    fclose(out);
    free(out_buf);
    unlink(path);
}

static struct event make(event_type_t type, const char *ip, time_t ts)
{
    struct event ev;
    event_init(&ev, type, type < EV_CONNECT ? EV_SOURCE_IDS : EV_SOURCE_HONEYPOT, ip);
    ev.timestamp = ts;
    return ev;
}

static void feed(event_type_t type, const char *ip, time_t ts)
{
    struct event ev = make(type, ip, ts);
    TEST_ASSERT_EQUAL_INT(0, correlator_process(c, &ev));
}

static threat_level_t level_of(const char *ip)
{
    const struct incident *inc = correlator_incident(c, ip);
    TEST_ASSERT_NOT_NULL(inc);
    return inc->level;
}

static const char *alerts(void)
{
    fflush(out);
    return out_buf;
}

static int count_char(const char *s, char ch)
{
    int n = 0;
    for (; *s; s++)
        n += *s == ch;
    return n;
}

static void test_first_event_opens_low_incident(void)
{
    feed(EV_CONNECT, "1.1.1.1", 1000);
    TEST_ASSERT_EQUAL(THREAT_LOW, level_of("1.1.1.1"));
    TEST_ASSERT_NOT_NULL(strstr(alerts(), "(new)"));
    TEST_ASSERT_EQUAL_INT64(1, query_int(check, "SELECT COUNT(*) FROM incidents"));
    TEST_ASSERT_NULL(correlator_incident(c, "2.2.2.2"));
}

static void test_full_attack_chain_is_high(void)
{
    const char *ip = "45.1.2.3";
    feed(EV_PORT_SCAN, ip, 1000);
    TEST_ASSERT_EQUAL(THREAT_LOW, level_of(ip));

    feed(EV_LOGIN_ATTEMPT, ip, 1010);
    feed(EV_LOGIN_ATTEMPT, ip, 1011);
    TEST_ASSERT_EQUAL(THREAT_LOW, level_of(ip));
    feed(EV_LOGIN_ATTEMPT, ip, 1012);
    TEST_ASSERT_EQUAL(THREAT_MEDIUM, level_of(ip));

    feed(EV_LOGIN_SUCCESS, ip, 1013);
    TEST_ASSERT_EQUAL(THREAT_HIGH, level_of(ip));

    feed(EV_COMMAND, ip, 1020);
    feed(EV_DOWNLOAD_ATTEMPT, ip, 1030);

    const struct incident *inc = correlator_incident(c, ip);
    TEST_ASSERT_EQUAL_INT(7, inc->event_count);
    TEST_ASSERT_EQUAL_INT64(1000, inc->first_seen);
    TEST_ASSERT_EQUAL_INT64(1030, inc->last_seen);

    TEST_ASSERT_EQUAL_INT64(1, query_int(check, "SELECT COUNT(*) FROM incidents"));
    char buf[16];
    query_text(check, "SELECT level FROM incidents", buf, sizeof buf);
    TEST_ASSERT_EQUAL_STRING("HIGH", buf);
    TEST_ASSERT_EQUAL_INT64(7, query_int(check, "SELECT event_count FROM incidents"));
    TEST_ASSERT_EQUAL_INT64(7, query_int(check,
        "SELECT COUNT(*) FROM events WHERE incident_id = (SELECT id FROM incidents)"));

    const char *a = alerts();
    TEST_ASSERT_NOT_NULL(strstr(a, "LOW -> MEDIUM"));
    TEST_ASSERT_NOT_NULL(strstr(a, "MEDIUM -> HIGH"));
    TEST_ASSERT_EQUAL_INT(3, count_char(a, '\n'));
}

static void test_login_without_scan_is_medium(void)
{
    feed(EV_LOGIN_SUCCESS, "3.3.3.3", 1000);
    TEST_ASSERT_EQUAL(THREAT_MEDIUM, level_of("3.3.3.3"));
}

static void test_download_is_high(void)
{
    feed(EV_DOWNLOAD_ATTEMPT, "4.4.4.4", 1000);
    TEST_ASSERT_EQUAL(THREAT_HIGH, level_of("4.4.4.4"));
}

static void test_ids_attacks_are_medium(void)
{
    feed(EV_SYN_FLOOD, "5.5.5.5", 1000);
    feed(EV_ARP_SPOOF, "6.6.6.6", 1000);
    TEST_ASSERT_EQUAL(THREAT_MEDIUM, level_of("5.5.5.5"));
    TEST_ASSERT_EQUAL(THREAT_MEDIUM, level_of("6.6.6.6"));
}

static void test_ips_are_separate_incidents(void)
{
    feed(EV_PORT_SCAN, "7.7.7.7", 1000);
    feed(EV_LOGIN_SUCCESS, "8.8.8.8", 1001);
    TEST_ASSERT_EQUAL(THREAT_LOW, level_of("7.7.7.7"));
    TEST_ASSERT_EQUAL(THREAT_MEDIUM, level_of("8.8.8.8"));
    TEST_ASSERT_EQUAL_INT64(2, query_int(check, "SELECT COUNT(*) FROM incidents"));
}

static void test_timeout_starts_new_incident(void)
{
    feed(EV_DOWNLOAD_ATTEMPT, "9.9.9.9", 1000);
    feed(EV_CONNECT, "9.9.9.9", 1000 + TIMEOUT);
    TEST_ASSERT_EQUAL(THREAT_HIGH, level_of("9.9.9.9"));

    feed(EV_CONNECT, "9.9.9.9", 1000 + 2 * TIMEOUT + 1);
    TEST_ASSERT_EQUAL(THREAT_LOW, level_of("9.9.9.9"));
    TEST_ASSERT_EQUAL_INT(1, correlator_incident(c, "9.9.9.9")->event_count);
    TEST_ASSERT_EQUAL_INT64(2, query_int(check, "SELECT COUNT(*) FROM incidents"));
}

static void test_alert_strips_control_chars(void)
{
    struct event ev = make(EV_COMMAND, "10.0.0.1", 1000);
    event_set_str(ev.details, sizeof ev.details, "\033[2J\033]0;pwned\007rm -rf /\n");
    TEST_ASSERT_EQUAL_INT(0, correlator_process(c, &ev));

    const char *a = alerts();
    TEST_ASSERT_NULL(strchr(a, '\033'));
    TEST_ASSERT_NULL(strchr(a, '\007'));
    TEST_ASSERT_EQUAL_INT(1, count_char(a, '\n'));
    TEST_ASSERT_NOT_NULL(strstr(a, "rm -rf /"));

    char buf[64];
    query_text(check, "SELECT details FROM events", buf, sizeof buf);
    TEST_ASSERT_EQUAL_STRING(ev.details, buf);
}

static void test_run_drains_queue(void)
{
    struct event_queue *q = queue_create(8);
    TEST_ASSERT_NOT_NULL(q);
    for (int i = 0; i < 5; i++) {
        struct event ev = make(EV_LOGIN_ATTEMPT, "11.0.0.1", 1000 + i);
        TEST_ASSERT_EQUAL_INT(0, queue_push(q, &ev));
    }
    queue_close(q);

    correlator_run(c, q);
    queue_destroy(q);

    TEST_ASSERT_EQUAL_INT(5, correlator_incident(c, "11.0.0.1")->event_count);
    TEST_ASSERT_EQUAL_INT64(5, query_int(check, "SELECT COUNT(*) FROM events"));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_first_event_opens_low_incident);
    RUN_TEST(test_full_attack_chain_is_high);
    RUN_TEST(test_login_without_scan_is_medium);
    RUN_TEST(test_download_is_high);
    RUN_TEST(test_ids_attacks_are_medium);
    RUN_TEST(test_ips_are_separate_incidents);
    RUN_TEST(test_timeout_starts_new_incident);
    RUN_TEST(test_alert_strips_control_chars);
    RUN_TEST(test_run_drains_queue);
    return UNITY_END();
}
