#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

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

static int count_port_scans(void)
{
    int n = 0;
    for (int i = 0; i < nevents && i < MAX_EVENTS; i++)
        if (events[i].type == EV_PORT_SCAN)
            n++;
    return n;
}

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
    TEST_ASSERT_EQUAL_INT64(200, st.packets);
    TEST_ASSERT_EQUAL_INT64(200, st.ipv4);
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

static void test_bad_interface(void)
{
    volatile sig_atomic_t stop = 0;
    struct capture_stats st;
    TEST_ASSERT_EQUAL_INT(-1, capture_live("no-such-if0", &DEFAULTS, collect, NULL,
                                           &stop, &st));
}

static volatile sig_atomic_t live_stop;
static struct capture_stats live_stats;
static int live_rc;

static void *live_thread(void *arg)
{
    (void)arg;
    live_rc = capture_live("lo", &DEFAULTS, collect, NULL, &live_stop, &live_stats);
    return NULL;
}

static void knock(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    (void)connect(fd, (struct sockaddr *)&addr, sizeof addr);
    close(fd);
}

static void test_live_capture_on_loopback(void)
{
    if (geteuid() != 0)
        TEST_IGNORE_MESSAGE("needs root: sudo ./build/tests/test_capture");

    live_stop = 0;
    pthread_t t;
    TEST_ASSERT_EQUAL_INT(0, pthread_create(&t, NULL, live_thread, NULL));
    sleep(1);

    for (uint16_t port = 1; port <= 30; port++)
        knock(port);

    sleep(1);
    live_stop = 1;
    pthread_join(t, NULL);

    TEST_ASSERT_EQUAL_INT(0, live_rc);
    TEST_ASSERT_EQUAL_INT(1, count_port_scans());
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_counts_all_packets);
    RUN_TEST(test_port_scan_found_in_real_capture);
    RUN_TEST(test_thresholds_are_used);
    RUN_TEST(test_missing_file);
    RUN_TEST(test_bad_thresholds);
    RUN_TEST(test_bad_interface);
    RUN_TEST(test_live_capture_on_loopback);
    return UNITY_END();
}