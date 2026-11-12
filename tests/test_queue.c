#include <pthread.h>
#include <stdint.h>
#include <time.h>

#include "unity.h"
#include "core/queue.h"

#define PRODUCERS    4
#define PER_PRODUCER 10000

static struct event_queue *q;

void setUp(void)
{
    q = NULL;
}

void tearDown(void)
{
    queue_destroy(q);
}

static struct event make_event(uint32_t id)
{
    struct event ev;
    event_init(&ev, EV_COMMAND, EV_SOURCE_HONEYPOT, "10.0.0.1");
    ev.session_id = id;
    return ev;
}

static void push_id(uint32_t id)
{
    struct event ev = make_event(id);
    TEST_ASSERT_EQUAL_INT(0, queue_push(q, &ev));
}

static void pop_expect(uint32_t id)
{
    struct event ev;
    TEST_ASSERT_EQUAL_INT(0, queue_pop(q, &ev));
    TEST_ASSERT_EQUAL_UINT32(id, ev.session_id);
}

static void let_thread_block(void)
{
    struct timespec ts = { 0, 50 * 1000 * 1000 };
    nanosleep(&ts, NULL);
}

static void test_create_zero_capacity(void)
{
    TEST_ASSERT_NULL(queue_create(0));
}

static void test_fifo(void)
{
    q = queue_create(8);
    TEST_ASSERT_NOT_NULL(q);
    push_id(1);
    push_id(2);
    push_id(3);
    pop_expect(1);
    pop_expect(2);
    pop_expect(3);
}

static void test_wraparound(void)
{
    q = queue_create(3);
    TEST_ASSERT_NOT_NULL(q);
    push_id(0);
    push_id(1);
    for (uint32_t i = 2; i < 12; i++) {
        push_id(i);
        pop_expect(i - 2);
    }
    pop_expect(10);
    pop_expect(11);
}

static void test_pop_on_closed_empty(void)
{
    q = queue_create(4);
    TEST_ASSERT_NOT_NULL(q);
    queue_close(q);
    struct event ev;
    TEST_ASSERT_EQUAL_INT(-1, queue_pop(q, &ev));
}

static void test_close_drains_remaining(void)
{
    q = queue_create(4);
    TEST_ASSERT_NOT_NULL(q);
    push_id(1);
    push_id(2);
    queue_close(q);
    pop_expect(1);
    pop_expect(2);
    struct event ev;
    TEST_ASSERT_EQUAL_INT(-1, queue_pop(q, &ev));
}

static void test_push_after_close(void)
{
    q = queue_create(4);
    TEST_ASSERT_NOT_NULL(q);
    queue_close(q);
    struct event ev = make_event(1);
    TEST_ASSERT_EQUAL_INT(-1, queue_push(q, &ev));
}

struct producer_arg {
    uint32_t id;
    int      failed;
};

static void *producer(void *p)
{
    struct producer_arg *a = p;
    for (uint32_t i = 0; i < PER_PRODUCER; i++) {
        struct event ev = make_event(a->id * PER_PRODUCER + i);
        if (queue_push(q, &ev) != 0)
            a->failed++;
    }
    return NULL;
}

static void test_many_producers(void)
{
    q = queue_create(16);
    TEST_ASSERT_NOT_NULL(q);

    pthread_t threads[PRODUCERS];
    struct producer_arg args[PRODUCERS];
    for (uint32_t p = 0; p < PRODUCERS; p++) {
        args[p] = (struct producer_arg){ .id = p, .failed = 0 };
        TEST_ASSERT_EQUAL_INT(0, pthread_create(&threads[p], NULL, producer, &args[p]));
    }

    uint32_t next[PRODUCERS] = { 0 };
    for (int i = 0; i < PRODUCERS * PER_PRODUCER; i++) {
        struct event ev;
        TEST_ASSERT_EQUAL_INT(0, queue_pop(q, &ev));
        uint32_t p = ev.session_id / PER_PRODUCER;
        TEST_ASSERT_LESS_THAN_UINT32(PRODUCERS, p);
        TEST_ASSERT_EQUAL_UINT32(next[p], ev.session_id % PER_PRODUCER);
        next[p]++;
    }

    for (int p = 0; p < PRODUCERS; p++) {
        TEST_ASSERT_EQUAL_INT(0, pthread_join(threads[p], NULL));
        TEST_ASSERT_EQUAL_INT(0, args[p].failed);
        TEST_ASSERT_EQUAL_UINT32(PER_PRODUCER, next[p]);
    }

    queue_close(q);
    struct event ev;
    TEST_ASSERT_EQUAL_INT(-1, queue_pop(q, &ev));
}

static void *blocked_pop(void *p)
{
    struct event ev;
    *(int *)p = queue_pop(q, &ev);
    return NULL;
}

static void *blocked_push(void *p)
{
    struct event ev = make_event(2);
    *(int *)p = queue_push(q, &ev);
    return NULL;
}

static void test_close_wakes_consumer(void)
{
    q = queue_create(4);
    TEST_ASSERT_NOT_NULL(q);

    pthread_t t;
    int rc = 0;
    TEST_ASSERT_EQUAL_INT(0, pthread_create(&t, NULL, blocked_pop, &rc));
    let_thread_block();
    queue_close(q);
    TEST_ASSERT_EQUAL_INT(0, pthread_join(t, NULL));
    TEST_ASSERT_EQUAL_INT(-1, rc);
}

static void test_close_wakes_producer(void)
{
    q = queue_create(1);
    TEST_ASSERT_NOT_NULL(q);
    push_id(1);

    pthread_t t;
    int rc = 0;
    TEST_ASSERT_EQUAL_INT(0, pthread_create(&t, NULL, blocked_push, &rc));
    let_thread_block();
    queue_close(q);
    TEST_ASSERT_EQUAL_INT(0, pthread_join(t, NULL));
    TEST_ASSERT_EQUAL_INT(-1, rc);

    pop_expect(1);
    struct event ev;
    TEST_ASSERT_EQUAL_INT(-1, queue_pop(q, &ev));
}

static void test_sink_pushes_and_survives_close(void)
{
    q = queue_create(4);
    TEST_ASSERT_NOT_NULL(q);
    struct event ev = make_event(5);
    queue_sink(&ev, q);
    queue_close(q);
    queue_sink(&ev, q);
    pop_expect(5);
    TEST_ASSERT_EQUAL_INT(-1, queue_pop(q, &ev));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_sink_pushes_and_survives_close);
    RUN_TEST(test_create_zero_capacity);
    RUN_TEST(test_fifo);
    RUN_TEST(test_wraparound);
    RUN_TEST(test_pop_on_closed_empty);
    RUN_TEST(test_close_drains_remaining);
    RUN_TEST(test_push_after_close);
    RUN_TEST(test_many_producers);
    RUN_TEST(test_close_wakes_consumer);
    RUN_TEST(test_close_wakes_producer);
    return UNITY_END();
}
