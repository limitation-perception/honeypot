#include "unity.h"
#include "ids/capture.h"

void setUp(void) {}
void tearDown(void) {}

static void test_counts_all_packets(void)
{
    struct capture_stats st;
    TEST_ASSERT_EQUAL_INT(0, capture_read_file("samples/portscan.pcap", &st));
    TEST_ASSERT_EQUAL_INT64(400, st.packets);
    TEST_ASSERT_EQUAL_INT64(400, st.ipv4);
    TEST_ASSERT_EQUAL_INT64(200, st.syn); 
    TEST_ASSERT_EQUAL_INT64(0, st.bad);
}

static void test_missing_file(void)
{
    struct capture_stats st;
    TEST_ASSERT_EQUAL_INT(-1, capture_read_file("samples/no-such-file.pcap", &st));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_counts_all_packets);
    RUN_TEST(test_missing_file);
    return UNITY_END();
}