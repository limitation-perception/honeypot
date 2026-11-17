#include <string.h>

#include "unity.h"
#include "ids/detectors.h"

#define MAX_EVENTS 16

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

static struct detectors *d;

void setUp(void)
{
    nevents = 0;
    memset(events, 0, sizeof events);
    d = detectors_create(&DEFAULTS, collect, NULL);
    TEST_ASSERT_NOT_NULL(d);
}

void tearDown(void)
{
    detectors_destroy(d);
}

#define SEC 1000000LL
#define MS  1000LL
#define T0  (1763380000LL * SEC)

#define ATTACKER 0x0a000042u
#define VICTIM   0x0a000002u

static void tcp(int64_t t, uint32_t src, uint32_t dst, uint16_t port, uint8_t flags)
{
    struct packet p;
    memset(&p, 0, sizeof p);
    p.has_ipv4 = true;
    p.has_tcp = true;
    p.ip_src = src;
    p.ip_dst = dst;
    p.dst_port = port;
    p.tcp_flags = flags;
    detectors_feed(d, &p, t);
}

static void scan(int64_t start, uint32_t src, int ports, int64_t step)
{
    for (int i = 0; i < ports; i++)
        tcp(start + i * step, src, VICTIM, (uint16_t)(1 + i), TCP_SYN);
}

static void test_create_rejects_bad_input(void)
{
    struct ids_thresholds th = DEFAULTS;
    th.portscan_ports = 0;
    TEST_ASSERT_NULL(detectors_create(&th, collect, NULL));

    th = DEFAULTS;
    th.synflood_window_sec = -1;
    TEST_ASSERT_NULL(detectors_create(&th, collect, NULL));

    TEST_ASSERT_NULL(detectors_create(NULL, collect, NULL));
    TEST_ASSERT_NULL(detectors_create(&DEFAULTS, NULL, NULL));
}

static void test_port_scan_detected(void)
{
    scan(T0, ATTACKER, 20, 10 * MS);

    TEST_ASSERT_EQUAL_INT(1, nevents);
    TEST_ASSERT_EQUAL(EV_PORT_SCAN, events[0].type);
    TEST_ASSERT_EQUAL(EV_SOURCE_IDS, events[0].source);
    TEST_ASSERT_EQUAL_STRING("10.0.0.66", events[0].src_ip);
    TEST_ASSERT_EQUAL_INT64(T0 / SEC, (int64_t)events[0].timestamp);
    TEST_ASSERT_EQUAL_STRING("20 ports in 0.2s to 10.0.0.2", events[0].details);
}

static void test_below_threshold(void)
{
    scan(T0, ATTACKER, 19, 10 * MS);
    TEST_ASSERT_EQUAL_INT(0, nevents);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_create_rejects_bad_input);
    RUN_TEST(test_port_scan_detected);
    RUN_TEST(test_below_threshold);
    return UNITY_END();
}