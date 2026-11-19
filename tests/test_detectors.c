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
#define GATEWAY  0x0a000001u

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

static void arp(int64_t t, uint32_t ip, uint8_t mac_last)
{
    struct packet p;
    memset(&p, 0, sizeof p);
    p.has_arp = true;
    p.arp_op = ARP_OP_REPLY;
    p.arp_spa = ip;
    uint8_t mac[MAC_LEN] = { 0x02, 0x00, 0x00, 0x00, 0x00, mac_last };
    memcpy(p.arp_sha, mac, MAC_LEN);
    detectors_feed(d, &p, t);
}

static int count_type(event_type_t type)
{
    int n = 0;
    for (int i = 0; i < nevents && i < MAX_EVENTS; i++)
        if (events[i].type == type)
            n++;
    return n;
}

static void scan(int64_t start, uint32_t src, int ports, int64_t step)
{
    for (int i = 0; i < ports; i++)
        tcp(start + i * step, src, VICTIM, (uint16_t)(1 + i), TCP_SYN);
}

static void flood(int64_t start, uint32_t src, int count, int64_t step)
{
    for (int i = 0; i < count; i++)
        tcp(start + i * step, src, VICTIM, 8080, TCP_SYN);
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

static void test_slow_scan_is_not_detected(void)
{
    scan(T0, ATTACKER, 40, 200 * MS);
    TEST_ASSERT_EQUAL_INT(0, nevents);
}

static void test_same_port_many_times(void)
{
    for (int i = 0; i < 500; i++)
        tcp(T0 + i * MS, ATTACKER, VICTIM, 80, TCP_SYN);
    TEST_ASSERT_EQUAL_INT(0, count_type(EV_PORT_SCAN));
}

static void test_ack_and_rst_are_not_probes(void)
{
    for (int i = 0; i < 100; i++) {
        tcp(T0 + i * MS, ATTACKER, VICTIM, (uint16_t)(1000 + i), TCP_ACK);
        tcp(T0 + i * MS, ATTACKER, VICTIM, (uint16_t)(2000 + i), TCP_SYN | TCP_ACK);
        tcp(T0 + i * MS, ATTACKER, VICTIM, (uint16_t)(3000 + i), TCP_RST);
    }
    TEST_ASSERT_EQUAL_INT(0, nevents);
}

static void test_stealth_scans(void)
{
    const uint8_t kinds[] = { TCP_FIN, 0, TCP_FIN | TCP_PSH | TCP_URG };
    for (int k = 0; k < 3; k++)
        for (int i = 0; i < 20; i++)
            tcp(T0 + i * MS, ATTACKER + (uint32_t)k, VICTIM, (uint16_t)(100 + i), kinds[k]);
    TEST_ASSERT_EQUAL_INT(3, nevents);
}

static void test_long_scan_reported_once(void)
{
    scan(T0, ATTACKER, 1000, 1 * MS);
    TEST_ASSERT_EQUAL_INT(1, nevents);
}

static void test_new_scan_after_silence(void)
{
    scan(T0, ATTACKER, 20, MS);
    scan(T0 + 10 * SEC, ATTACKER, 20, MS);
    TEST_ASSERT_EQUAL_INT(2, nevents);
}

static void test_scanners_are_separate(void)
{
    for (int i = 0; i < 10; i++) {
        tcp(T0 + i * MS, ATTACKER, VICTIM, (uint16_t)(1 + i), TCP_SYN);
        tcp(T0 + i * MS, ATTACKER + 1, VICTIM, (uint16_t)(100 + i), TCP_SYN);
    }
    TEST_ASSERT_EQUAL_INT(0, nevents);
}

static void test_many_ips_do_not_break_tracking(void)
{
    for (uint32_t i = 0; i < 10000; i++)
        tcp(T0 + i, 0x64000000u + i, VICTIM, 80, TCP_SYN);
    scan(T0 + 10 * SEC, ATTACKER, 20, MS);
    TEST_ASSERT_EQUAL_INT(1, count_type(EV_PORT_SCAN));
}

static void test_syn_flood_detected(void)
{
    flood(T0, ATTACKER, 100, 5 * MS);

    TEST_ASSERT_EQUAL_INT(1, nevents);
    TEST_ASSERT_EQUAL(EV_SYN_FLOOD, events[0].type);
    TEST_ASSERT_EQUAL_STRING("10.0.0.66", events[0].src_ip);
    TEST_ASSERT_EQUAL_UINT16(8080, events[0].dst_port);
    TEST_ASSERT_EQUAL_STRING("100 SYN to 10.0.0.2:8080 in 1s from 1 source", events[0].details);
}

static void test_flood_below_threshold(void)
{
    flood(T0, ATTACKER, 99, 5 * MS);
    TEST_ASSERT_EQUAL_INT(0, nevents);
}

static void test_syn_rate_too_low(void)
{
    flood(T0, ATTACKER, 300, 11 * MS);
    TEST_ASSERT_EQUAL_INT(0, nevents);
}

static void test_long_flood_reported_once(void)
{
    flood(T0, ATTACKER, 5000, 1 * MS);
    TEST_ASSERT_EQUAL_INT(1, nevents);
}

static void test_flood_again_after_pause(void)
{
    flood(T0, ATTACKER, 200, MS);
    flood(T0 + 60 * SEC, ATTACKER, 200, MS);
    TEST_ASSERT_EQUAL_INT(2, nevents);
}

static void test_spoofed_flood(void)
{
    for (int i = 0; i < 150; i++)
        tcp(T0 + i * MS, 0x01020000u + (uint32_t)i * 7919, VICTIM, 80, TCP_SYN);

    TEST_ASSERT_EQUAL_INT(1, nevents);
    TEST_ASSERT_EQUAL(EV_SYN_FLOOD, events[0].type);
    TEST_ASSERT_NOT_NULL(strstr(events[0].details, "8+ sources (spoofed?)"));
}

static void test_flood_blames_top_source(void)
{
    for (int i = 0; i < 100; i++)
        tcp(T0 + i * MS, (i % 4 == 0) ? VICTIM + 100 : ATTACKER, VICTIM, 80, TCP_SYN);

    TEST_ASSERT_EQUAL_INT(1, nevents);
    TEST_ASSERT_EQUAL_STRING("10.0.0.66", events[0].src_ip);
    TEST_ASSERT_NOT_NULL(strstr(events[0].details, "from 2 sources"));
}

static void test_syn_ack_is_not_flood(void)
{
    for (int i = 0; i < 500; i++)
        tcp(T0 + i * MS, ATTACKER, VICTIM, 80, TCP_SYN | TCP_ACK);
    TEST_ASSERT_EQUAL_INT(0, nevents);
}

static void test_fast_scan_is_not_flood(void)
{
    for (int i = 0; i < 1000; i++)
        tcp(T0 + i * 100, ATTACKER, VICTIM, (uint16_t)(1 + i), TCP_SYN);
    TEST_ASSERT_EQUAL_INT(1, count_type(EV_PORT_SCAN));
    TEST_ASSERT_EQUAL_INT(0, count_type(EV_SYN_FLOOD));
}

static void test_floods_on_two_ports_are_separate(void)
{
    for (int i = 0; i < 100; i++) {
        tcp(T0 + i * MS, ATTACKER, VICTIM, 80, TCP_SYN);
        tcp(T0 + i * MS, ATTACKER, VICTIM, 443, TCP_SYN);
    }
    TEST_ASSERT_EQUAL_INT(2, count_type(EV_SYN_FLOOD));
}

static void test_consistent_arp_is_fine(void)
{
    for (int i = 0; i < 50; i++) {
        arp(T0 + i * SEC, GATEWAY, 0x01);
        arp(T0 + i * SEC, VICTIM, 0x02);
    }
    TEST_ASSERT_EQUAL_INT(0, nevents);
}

static void test_arp_spoof_detected(void)
{
    arp(T0, GATEWAY, 0x01);
    arp(T0, ATTACKER, 0x66);
    arp(T0 + SEC, GATEWAY, 0x66);

    TEST_ASSERT_EQUAL_INT(1, nevents);
    TEST_ASSERT_EQUAL(EV_ARP_SPOOF, events[0].type);
    TEST_ASSERT_EQUAL(EV_SOURCE_IDS, events[0].source);
    TEST_ASSERT_EQUAL_STRING("10.0.0.66", events[0].src_ip);
    TEST_ASSERT_EQUAL_STRING("10.0.0.1 is-at 02:00:00:00:00:66 (was 02:00:00:00:00:01), "
                             "MAC owner: 10.0.0.66", events[0].details);
}

static void test_arp_spoof_unknown_owner(void)
{
    arp(T0, GATEWAY, 0x01);
    arp(T0 + SEC, GATEWAY, 0x99);

    TEST_ASSERT_EQUAL_INT(1, nevents);
    TEST_ASSERT_EQUAL_STRING("10.0.0.1", events[0].src_ip);
    TEST_ASSERT_NOT_NULL(strstr(events[0].details, "MAC owner: unknown"));
}

static void test_arp_spoof_not_repeated(void)
{
    arp(T0, GATEWAY, 0x01);
    for (int i = 1; i <= 25; i++) {
        arp(T0 + i * 2 * SEC, GATEWAY, 0x66);
        arp(T0 + i * 2 * SEC + 1, GATEWAY, 0x01);
    }
    TEST_ASSERT_EQUAL_INT(1, nevents);

    arp(T0 + (2 + IDS_ARP_REALERT_SEC) * SEC, GATEWAY, 0x66);
    TEST_ASSERT_EQUAL_INT(2, nevents);
}

static void test_second_attacker_is_reported(void)
{
    arp(T0, GATEWAY, 0x01);
    arp(T0 + SEC, GATEWAY, 0x66);
    arp(T0 + 2 * SEC, GATEWAY, 0x77);
    TEST_ASSERT_EQUAL_INT(2, nevents);
}

static void test_arp_probe_ignored(void)
{
    arp(T0, 0, 0x01);
    arp(T0 + SEC, 0, 0x02);
    TEST_ASSERT_EQUAL_INT(0, nevents);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_create_rejects_bad_input);
    RUN_TEST(test_port_scan_detected);
    RUN_TEST(test_below_threshold);
    RUN_TEST(test_slow_scan_is_not_detected);
    RUN_TEST(test_same_port_many_times);
    RUN_TEST(test_ack_and_rst_are_not_probes);
    RUN_TEST(test_stealth_scans);
    RUN_TEST(test_long_scan_reported_once);
    RUN_TEST(test_new_scan_after_silence);
    RUN_TEST(test_scanners_are_separate);
    RUN_TEST(test_many_ips_do_not_break_tracking);
    RUN_TEST(test_syn_flood_detected);
    RUN_TEST(test_flood_below_threshold);
    RUN_TEST(test_syn_rate_too_low);
    RUN_TEST(test_long_flood_reported_once);
    RUN_TEST(test_flood_again_after_pause);
    RUN_TEST(test_spoofed_flood);
    RUN_TEST(test_flood_blames_top_source);
    RUN_TEST(test_syn_ack_is_not_flood);
    RUN_TEST(test_fast_scan_is_not_flood);
    RUN_TEST(test_floods_on_two_ports_are_separate);
    RUN_TEST(test_consistent_arp_is_fine);
    RUN_TEST(test_arp_spoof_detected);
    RUN_TEST(test_arp_spoof_unknown_owner);
    RUN_TEST(test_arp_spoof_not_repeated);
    RUN_TEST(test_second_attacker_is_reported);
    RUN_TEST(test_arp_probe_ignored);
    return UNITY_END();
}