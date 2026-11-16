#include "unity.h"
#include "ids/parser.h"

void setUp(void) {}
void tearDown(void) {}

static const uint8_t ARP_FRAME[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x66,
    0x08, 0x06,
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
}

static void test_too_short_frame(void)
{
    struct packet p;
    TEST_ASSERT_EQUAL_INT(-1, parse_ethernet(ARP_FRAME, 13, &p));
    TEST_ASSERT_EQUAL_INT(-1, parse_ethernet(ARP_FRAME, 0, &p));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_ethernet_header);
    RUN_TEST(test_too_short_frame);
    return UNITY_END();
}