#include <string.h>

#include "unity.h"
#include "ids/capture.h"

#define MAX_EVENTS 8

static struct event events[MAX_EVENTS];
static int nevents;

static void collect(const struct event *ev, void *ctx)
{
    (void)ctx;
    if (nevents < MAX_EVENTS)
        events[nevents] = *ev;
    nevents++;
}

static const struct ids_thresholds DEFAULTS = {
    .portscan_ports = 20,
    .portscan_window_sec = 3,
    .synflood_syns = 100,
    .synflood_window_sec = 1,
};

void setUp(void)
{
    nevents = 0;
    memset(events, 0, sizeof events);
}

void tearDown(void) {}

static void test_counts_all_packets(void)
{
    struct capture_stats st;
    TEST_ASSERT_EQUAL_INT(0, capture_read_file("samples/portscan.pcap", &DEFAULTS,
                                               collect, NULL, &st));
    TEST_ASSERT_EQUAL_INT64(400, st.packets);
    TEST_ASSERT_EQUAL_INT64(400, st.ipv4);
    TEST_ASSERT_EQUAL_INT64(200, st.syn);
    TEST_ASSERT_EQUAL_INT64(0, st.bad);
}

static void test_port_scan_found_in_real_capture(void)
{
    struct capture_stats st;
    TEST_ASSERT_EQUAL_INT(0, capture_read_file("samples/portscan.pcap", &DEFAULTS,
                                               collect, NULL, &st));

    TEST_ASSERT_EQUAL_INT(1, nevents);
    TEST_ASSERT_EQUAL(EV_PORT_SCAN, events[0].type);
    TEST_ASSERT_EQUAL(EV_SOURCE_IDS, events[0].source);
    TEST_ASSERT_EQUAL_STRING("127.0.0.1", events[0].src_ip);
    TEST_ASSERT_NOT_NULL(strstr(events[0].details, "20 ports"));
    TEST_ASSERT_NOT_NULL(strstr(events[0].details, "to 127.0.0.1"));
    TEST_ASSERT_TRUE(events[0].timestamp > 1700000000);
}

static void test_thresholds_are_used(void)
{
    struct ids_thresholds th = DEFAULTS;
    th.portscan_ports = 300;

    struct capture_stats st;
    TEST_ASSERT_EQUAL_INT(0, capture_read_file("samples/portscan.pcap", &th,
                                               collect, NULL, &st));
    TEST_ASSERT_EQUAL_INT(0, nevents);
}

static void test_missing_file(void)
{
    struct capture_stats st;
    TEST_ASSERT_EQUAL_INT(-1, capture_read_file("samples/no-such-file.pcap", &DEFAULTS,
                                                collect, NULL, &st));
}

static void test_bad_thresholds(void)
{
    struct ids_thresholds th = DEFAULTS;
    th.synflood_syns = 0;

    struct capture_stats st;
    TEST_ASSERT_EQUAL_INT(-1, capture_read_file("samples/portscan.pcap", &th,
                                                collect, NULL, &st));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_counts_all_packets);
    RUN_TEST(test_port_scan_found_in_real_capture);
    RUN_TEST(test_thresholds_are_used);
    RUN_TEST(test_missing_file);
    RUN_TEST(test_bad_thresholds);
    return UNITY_END();
}