#include <string.h>
#include "unity.h"
#include "ids/parser.h"

void setUp(void) {}
void tearDown(void) {}

static const uint8_t ARP_FRAME[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x66,
    0x08, 0x06,

    0x00, 0x01, 0x08, 0x00,
    0x06, 0x04, 0x00, 0x01,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x66,
    0x0a, 0x00, 0x00, 0x42,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x00, 0x01,
};

#define ARP_START 14

static const uint8_t SYN_FRAME[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x00,

    0x45, 0x00, 0x00, 0x2c,
    0x3d, 0x1a, 0x00, 0x00,
    0x35, 0x06, 0x4a, 0xb0,
    0x7f, 0x00, 0x00, 0x01,
    0x7f, 0x00, 0x00, 0x01,

    0xb4, 0xb0, 0x00, 0x50,
    0x7c, 0xcb, 0x09, 0x1c,
    0x00, 0x00, 0x00, 0x00,
    0x60, 0x02, 0x04, 0x00,
    0x5b, 0x3c, 0x00, 0x00,
    0x02, 0x04, 0x05, 0xb4,
};

#define IP_START  14
#define TCP_START (14 + 20)

static const uint8_t UDP_FRAME[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x00,
    0x45, 0x00, 0x00, 0x1c,
    0x00, 0x01, 0x00, 0x00,
    0x40, 0x11, 0x00, 0x00,
    0x0a, 0x00, 0x00, 0x02,
    0x08, 0x08, 0x08, 0x08,
    0x14, 0xe9, 0x00, 0x35,
    0x00, 0x08, 0x00, 0x00,
};

static void test_ethernet_header(void)
{
    struct packet p;
    TEST_ASSERT_EQUAL_INT(0, parse_ethernet(ARP_FRAME, sizeof ARP_FRAME, &p));

    const uint8_t broadcast[MAC_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    const uint8_t sender[MAC_LEN]    = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x66 };
    TEST_ASSERT_EQUAL_MEMORY(broadcast, p.eth_dst, MAC_LEN);
    TEST_ASSERT_EQUAL_MEMORY(sender, p.eth_src, MAC_LEN);
    TEST_ASSERT_EQUAL_HEX16(ETHERTYPE_ARP, p.ethertype);
    TEST_ASSERT_FALSE(p.has_ipv4);
}

static void test_too_short_frame(void)
{
    struct packet p;
    TEST_ASSERT_EQUAL_INT(-1, parse_ethernet(ARP_FRAME, 13, &p));
    TEST_ASSERT_EQUAL_INT(-1, parse_ethernet(ARP_FRAME, 0, &p));
}

static void test_ipv4_header(void)
{
    struct packet p;
    TEST_ASSERT_EQUAL_INT(0, parse_ethernet(SYN_FRAME, sizeof SYN_FRAME, &p));
    TEST_ASSERT_TRUE(p.has_ipv4);
    TEST_ASSERT_EQUAL_HEX32(0x7f000001, p.ip_src);
    TEST_ASSERT_EQUAL_HEX32(0x7f000001, p.ip_dst);
    TEST_ASSERT_EQUAL_UINT8(IP_PROTO_TCP, p.ip_proto);
}

static void test_ipv4_too_short(void)
{
    struct packet p;
    TEST_ASSERT_EQUAL_INT(-1, parse_ethernet(SYN_FRAME, IP_START + 19, &p));
}

static void test_ipv4_bad_version_or_length(void)
{
    struct packet p;
    uint8_t frame[sizeof SYN_FRAME];
    memcpy(frame, SYN_FRAME, sizeof frame);

    frame[IP_START] = 0x65;
    TEST_ASSERT_EQUAL_INT(-1, parse_ethernet(frame, sizeof frame, &p));

    frame[IP_START] = 0x44;
    TEST_ASSERT_EQUAL_INT(-1, parse_ethernet(frame, sizeof frame, &p));

    frame[IP_START] = 0x4f;
    TEST_ASSERT_EQUAL_INT(-1, parse_ethernet(frame, sizeof frame, &p));
}

static void test_tcp_header(void)
{
    struct packet p;
    TEST_ASSERT_EQUAL_INT(0, parse_ethernet(SYN_FRAME, sizeof SYN_FRAME, &p));
    TEST_ASSERT_TRUE(p.has_tcp);
    TEST_ASSERT_FALSE(p.has_udp);
    TEST_ASSERT_EQUAL_UINT16(46256, p.src_port);
    TEST_ASSERT_EQUAL_UINT16(80, p.dst_port);
    TEST_ASSERT_EQUAL_HEX8(TCP_SYN, p.tcp_flags);
}

static void test_tcp_flags_are_bits(void)
{
    struct packet p;
    uint8_t frame[sizeof SYN_FRAME];
    memcpy(frame, SYN_FRAME, sizeof frame);

    frame[TCP_START + 13] = TCP_SYN | TCP_ACK;
    TEST_ASSERT_EQUAL_INT(0, parse_ethernet(frame, sizeof frame, &p));
    TEST_ASSERT_TRUE(p.tcp_flags & TCP_SYN);
    TEST_ASSERT_TRUE(p.tcp_flags & TCP_ACK);
    TEST_ASSERT_FALSE(p.tcp_flags & TCP_RST);
}

static void test_tcp_too_short(void)
{
    struct packet p;
    TEST_ASSERT_EQUAL_INT(-1, parse_ethernet(SYN_FRAME, TCP_START + 19, &p));
    TEST_ASSERT_TRUE(p.has_ipv4);
    TEST_ASSERT_FALSE(p.has_tcp);
}

static void test_tcp_bad_header_length(void)
{
    struct packet p;
    uint8_t frame[sizeof SYN_FRAME];
    memcpy(frame, SYN_FRAME, sizeof frame);

    frame[TCP_START + 12] = 0x40;
    TEST_ASSERT_EQUAL_INT(-1, parse_ethernet(frame, sizeof frame, &p));
}

static void test_ip_total_len_limits_tcp(void)
{
    struct packet p;
    uint8_t frame[sizeof SYN_FRAME];
    memcpy(frame, SYN_FRAME, sizeof frame);

    frame[IP_START + 3] = 30;
    TEST_ASSERT_EQUAL_INT(-1, parse_ethernet(frame, sizeof frame, &p));
}

static void test_ethernet_padding_is_ignored(void)
{
    struct packet p;
    uint8_t frame[60] = {0};
    memcpy(frame, UDP_FRAME, sizeof UDP_FRAME);
    TEST_ASSERT_EQUAL_INT(0, parse_ethernet(frame, sizeof frame, &p));
    TEST_ASSERT_EQUAL_UINT16(53, p.dst_port);
}

static void test_non_first_fragment_has_no_ports(void)
{
    struct packet p;
    uint8_t frame[sizeof SYN_FRAME];
    memcpy(frame, SYN_FRAME, sizeof frame);

    frame[IP_START + 7] = 0xb9;
    TEST_ASSERT_EQUAL_INT(0, parse_ethernet(frame, sizeof frame, &p));
    TEST_ASSERT_TRUE(p.has_ipv4);
    TEST_ASSERT_FALSE(p.has_tcp);
    TEST_ASSERT_EQUAL_UINT16(0, p.dst_port);
}

static void test_udp_header(void)
{
    struct packet p;
    TEST_ASSERT_EQUAL_INT(0, parse_ethernet(UDP_FRAME, sizeof UDP_FRAME, &p));
    TEST_ASSERT_TRUE(p.has_udp);
    TEST_ASSERT_FALSE(p.has_tcp);
    TEST_ASSERT_EQUAL_HEX32(0x08080808, p.ip_dst);
    TEST_ASSERT_EQUAL_UINT16(5353, p.src_port);
    TEST_ASSERT_EQUAL_UINT16(53, p.dst_port);
}

static void test_udp_too_short(void)
{
    struct packet p;
    TEST_ASSERT_EQUAL_INT(-1, parse_ethernet(UDP_FRAME, sizeof UDP_FRAME - 1, &p));
}

static void test_arp_request(void)
{
    struct packet p;
    TEST_ASSERT_EQUAL_INT(0, parse_ethernet(ARP_FRAME, sizeof ARP_FRAME, &p));
    TEST_ASSERT_TRUE(p.has_arp);
    TEST_ASSERT_FALSE(p.has_ipv4);
    TEST_ASSERT_EQUAL_UINT16(ARP_OP_REQUEST, p.arp_op);

    const uint8_t sender[MAC_LEN] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x66 };
    TEST_ASSERT_EQUAL_MEMORY(sender, p.arp_sha, MAC_LEN);
    TEST_ASSERT_EQUAL_HEX32(0x0a000042, p.arp_spa);
    TEST_ASSERT_EQUAL_HEX32(0x0a000001, p.arp_tpa);
}

static void test_arp_too_short(void)
{
    struct packet p;
    TEST_ASSERT_EQUAL_INT(-1, parse_ethernet(ARP_FRAME, sizeof ARP_FRAME - 1, &p));
    TEST_ASSERT_FALSE(p.has_arp);
}

static void test_arp_for_other_networks_is_skipped(void)
{
    struct packet p;
    uint8_t frame[sizeof ARP_FRAME];
    memcpy(frame, ARP_FRAME, sizeof frame);

    frame[ARP_START + 1] = 6;
    TEST_ASSERT_EQUAL_INT(0, parse_ethernet(frame, sizeof frame, &p));
    TEST_ASSERT_FALSE(p.has_arp);
}

static void test_ipv4_to_str(void)
{
    char buf[16];
    ipv4_to_str(0x7f000001, buf, sizeof buf);
    TEST_ASSERT_EQUAL_STRING("127.0.0.1", buf);
    ipv4_to_str(0xffffffff, buf, sizeof buf);
    TEST_ASSERT_EQUAL_STRING("255.255.255.255", buf);
}

static void test_mac_to_str(void)
{
    const uint8_t mac[MAC_LEN] = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01 };
    char buf[MAC_STR_LEN];
    mac_to_str(mac, buf, sizeof buf);
    TEST_ASSERT_EQUAL_STRING("de:ad:be:ef:00:01", buf);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_ethernet_header);
    RUN_TEST(test_too_short_frame);
    RUN_TEST(test_ipv4_header);
    RUN_TEST(test_ipv4_too_short);
    RUN_TEST(test_ipv4_bad_version_or_length);
    RUN_TEST(test_tcp_header);
    RUN_TEST(test_tcp_flags_are_bits);
    RUN_TEST(test_tcp_too_short);
    RUN_TEST(test_tcp_bad_header_length);
    RUN_TEST(test_ip_total_len_limits_tcp);
    RUN_TEST(test_ethernet_padding_is_ignored);
    RUN_TEST(test_non_first_fragment_has_no_ports);
    RUN_TEST(test_udp_header);
    RUN_TEST(test_udp_too_short);
    RUN_TEST(test_arp_request);
    RUN_TEST(test_arp_too_short);
    RUN_TEST(test_arp_for_other_networks_is_skipped);
    RUN_TEST(test_mac_to_str);
    RUN_TEST(test_ipv4_to_str);
    return UNITY_END();
}