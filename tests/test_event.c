#include <string.h>

#include "unity.h"
#include "core/event.h"

void setUp(void) {}
void tearDown(void) {}

static void test_type_name_known(void)
{
    TEST_ASSERT_EQUAL_STRING("PORT_SCAN", event_type_name(EV_PORT_SCAN));
    TEST_ASSERT_EQUAL_STRING("LOGIN_ATTEMPT", event_type_name(EV_LOGIN_ATTEMPT));
    TEST_ASSERT_EQUAL_STRING("DISCONNECT", event_type_name(EV_DISCONNECT));
}

static void test_type_name_invalid(void)
{
    TEST_ASSERT_EQUAL_STRING("UNKNOWN", event_type_name(EV_TYPE_COUNT));
    TEST_ASSERT_EQUAL_STRING("UNKNOWN", event_type_name((event_type_t)-1));
}

static void test_set_str_fits(void)
{
    char buf[8];
    event_set_str(buf, sizeof buf, "root");
    TEST_ASSERT_EQUAL_STRING("root", buf);
}

static void test_set_str_truncates(void)
{
    char buf[8];
    memset(buf, 'X', sizeof buf);
    event_set_str(buf, sizeof buf, "0123456789");
    TEST_ASSERT_EQUAL_STRING("0123456", buf);
}

static void test_set_str_null(void)
{
    char buf[8] = "old";
    event_set_str(buf, sizeof buf, NULL);
    TEST_ASSERT_EQUAL_STRING("", buf);
}

static void test_init(void)
{
    struct event ev;
    memset(&ev, 0xAA, sizeof ev);
    event_init(&ev, EV_COMMAND, EV_SOURCE_HONEYPOT, "10.0.0.5");

    TEST_ASSERT_EQUAL(EV_COMMAND, ev.type);
    TEST_ASSERT_EQUAL(EV_SOURCE_HONEYPOT, ev.source);
    TEST_ASSERT_EQUAL_STRING("10.0.0.5", ev.src_ip);
    TEST_ASSERT_TRUE(ev.timestamp > 0);
    TEST_ASSERT_EQUAL_UINT16(0, ev.dst_port);
    TEST_ASSERT_EQUAL_UINT32(0, ev.session_id);
    TEST_ASSERT_EQUAL_STRING("", ev.username);
    TEST_ASSERT_EQUAL_STRING("", ev.details);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_type_name_known);
    RUN_TEST(test_type_name_invalid);
    RUN_TEST(test_set_str_fits);
    RUN_TEST(test_set_str_truncates);
    RUN_TEST(test_set_str_null);
    RUN_TEST(test_init);
    return UNITY_END();
}
