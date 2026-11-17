#include <string.h>
#include "unity.h"
#include "ids/parser.h"

void setUp(void) {}
void tearDown(void) {}

static const uint8_t ARP_FRAME[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x66,
    0x08, 0x06,
};

static const uint8_t SYN_FRAME[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x00,

    0x45, 0x00, 0x00, 0x2c,
    0x3d, 0x1a, 0x00, 0x00,
    0x35, 0x06, 0x4a, 0xb0,
    0x7f, 0x00, 0x00, 0x01,
    0x7f, 0x00, 0x00, 0x01,
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
    TEST_ASSERT_EQUAL_INT(-1, parse_ethernet(SYN_FRAME, 14 + 19, &p));
}

static void test_ipv4_bad_version_or_length(void)
{
    struct packet p;
    uint8_t frame[sizeof SYN_FRAME];
    memcpy(frame, SYN_FRAME, sizeof frame);

    frame[14] = 0x65;
    TEST_ASSERT_EQUAL_INT(-1, parse_ethernet(frame, sizeof frame, &p));

    frame[14] = 0x44;
    TEST_ASSERT_EQUAL_INT(-1, parse_ethernet(frame, sizeof frame, &p));

    frame[14] = 0x46;
    TEST_ASSERT_EQUAL_INT(-1, parse_ethernet(frame, sizeof frame, &p));
}

static void test_ipv4_to_str(void)
{
    char buf[16];
    ipv4_to_str(0x7f000001, buf, sizeof buf);
    TEST_ASSERT_EQUAL_STRING("127.0.0.1", buf);
    ipv4_to_str(0xffffffff, buf, sizeof buf);
    TEST_ASSERT_EQUAL_STRING("255.255.255.255", buf);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_ethernet_header);
    RUN_TEST(test_too_short_frame);
    RUN_TEST(test_ipv4_header);
    RUN_TEST(test_ipv4_too_short);
    RUN_TEST(test_ipv4_bad_version_or_length);
    RUN_TEST(test_ipv4_to_str);
    return UNITY_END();
}