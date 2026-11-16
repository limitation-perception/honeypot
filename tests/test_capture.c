#include "unity.h"
#include "ids/capture.h"

void setUp(void) {}
void tearDown(void) {}

static void test_counts_all_packets(void)
{
    TEST_ASSERT_EQUAL_INT64(400, capture_read_file("samples/portscan.pcap"));
}

static void test_missing_file(void)
{
    TEST_ASSERT_EQUAL_INT64(-1, capture_read_file("samples/no-such-file.pcap"));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_counts_all_packets);
    RUN_TEST(test_missing_file);
    return UNITY_END();
}