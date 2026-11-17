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

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_create_rejects_bad_input);
    return UNITY_END();
}