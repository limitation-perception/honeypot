#include "unity.h"
#include "config.h"

static struct config cfg;

void setUp(void)
{
    config_set_defaults(&cfg);
}

void tearDown(void) {}

static void test_valid_file(void)
{
    TEST_ASSERT_EQUAL_INT(0, config_load("tests/fixtures/valid.conf", &cfg));
    TEST_ASSERT_EQUAL_INT(2323, cfg.honeypot_port);
    TEST_ASSERT_EQUAL_INT(5, cfg.honeypot_login_after);
    TEST_ASSERT_EQUAL_INT(10, cfg.honeypot_max_clients);
    TEST_ASSERT_EQUAL_STRING("wlan0", cfg.ids_interface);
    TEST_ASSERT_EQUAL_STRING("capture.pcap", cfg.ids_pcap_file);
    TEST_ASSERT_EQUAL_INT(50, cfg.ids_portscan_ports);
    TEST_ASSERT_EQUAL_INT(5, cfg.ids_portscan_window_sec);
    TEST_ASSERT_EQUAL_INT(500, cfg.ids_synflood_syns);
    TEST_ASSERT_EQUAL_INT(2, cfg.ids_synflood_window_sec);
    TEST_ASSERT_EQUAL_INT(64, cfg.core_queue_capacity);
    TEST_ASSERT_EQUAL_STRING("test.db", cfg.storage_db_path);
    TEST_ASSERT_EQUAL_STRING("out.html", cfg.storage_report_path);
}

static void test_partial_file_keeps_defaults(void)
{
    struct config defaults;
    config_set_defaults(&defaults);

    TEST_ASSERT_EQUAL_INT(0, config_load("tests/fixtures/partial.conf", &cfg));
    TEST_ASSERT_EQUAL_INT(2323, cfg.honeypot_port);
    TEST_ASSERT_EQUAL_INT(defaults.honeypot_login_after, cfg.honeypot_login_after);
    TEST_ASSERT_EQUAL_STRING(defaults.ids_interface, cfg.ids_interface);
    TEST_ASSERT_EQUAL_STRING(defaults.storage_db_path, cfg.storage_db_path);
}

static void test_shipped_config_loads(void)
{
    TEST_ASSERT_EQUAL_INT(0, config_load(CONFIG_DEFAULT_PATH, &cfg));
    TEST_ASSERT_EQUAL_STRING("", cfg.ids_pcap_file);
}

static void test_unknown_key(void)
{
    TEST_ASSERT_EQUAL_INT(-1, config_load("tests/fixtures/bad_key.conf", &cfg));
}

static void test_port_out_of_range(void)
{
    TEST_ASSERT_EQUAL_INT(-1, config_load("tests/fixtures/bad_port.conf", &cfg));
}

static void test_not_a_number(void)
{
    TEST_ASSERT_EQUAL_INT(-1, config_load("tests/fixtures/bad_number.conf", &cfg));
}

static void test_line_without_equals(void)
{
    TEST_ASSERT_EQUAL_INT(-1, config_load("tests/fixtures/no_equals.conf", &cfg));
}

static void test_missing_file(void)
{
    TEST_ASSERT_EQUAL_INT(-1, config_load("tests/fixtures/does_not_exist.conf", &cfg));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_valid_file);
    RUN_TEST(test_partial_file_keeps_defaults);
    RUN_TEST(test_shipped_config_loads);
    RUN_TEST(test_unknown_key);
    RUN_TEST(test_port_out_of_range);
    RUN_TEST(test_not_a_number);
    RUN_TEST(test_line_without_equals);
    RUN_TEST(test_missing_file);
    return UNITY_END();
}
