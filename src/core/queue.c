#include "core/queue.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "core/log.h"

#define CHECK_PTHREAD(call)                                   \
    do {                                                      \
        int rc_ = (call);                                     \
        if (rc_ != 0) {                                       \
            LOG_ERROR("%s: %s", #call, strerror(rc_));        \
            abort();                                          \
        }                                                     \
    } while (0)

struct event_queue {
    struct event   *items;
    size_t          capacity;
    size_t          head;
    size_t          count;
    bool            closed;
    pthread_mutex_t lock;
    pthread_cond_t  not_empty;
    pthread_cond_t  not_full;
};

struct event_queue *queue_create(size_t capacity)
{
    if (capacity == 0) {
        LOG_ERROR("queue capacity must be > 0");
        return NULL;
    }

    struct event_queue *q = calloc(1, sizeof *q);
    if (!q) {
        LOG_ERROR("cannot allocate queue");
        return NULL;
    }
    q->items = calloc(capacity, sizeof *q->items);
    if (!q->items) {
        LOG_ERROR("cannot allocate queue of %zu events", capacity);
        free(q);
        return NULL;
    }
    q->capacity = capacity;

    int rc = pthread_mutex_init(&q->lock, NULL);
    if (rc != 0) {
        LOG_ERROR("pthread_mutex_init: %s", strerror(rc));
        goto fail_items;
    }
    rc = pthread_cond_init(&q->not_empty, NULL);
    if (rc != 0) {
        LOG_ERROR("pthread_cond_init: %s", strerror(rc));
        goto fail_lock;
    }
    rc = pthread_cond_init(&q->not_full, NULL);
    if (rc != 0) {
        LOG_ERROR("pthread_cond_init: %s", strerror(rc));
        goto fail_not_empty;
    }
    return q;

fail_not_empty:
    pthread_cond_destroy(&q->not_empty);
fail_lock:
    pthread_mutex_destroy(&q->lock);
fail_items:
    free(q->items);
    free(q);
    return NULL;
}

void queue_destroy(struct event_queue *q)
{
    if (!q)
        return;
    CHECK_PTHREAD(pthread_cond_destroy(&q->not_full));
    CHECK_PTHREAD(pthread_cond_destroy(&q->not_empty));
    CHECK_PTHREAD(pthread_mutex_destroy(&q->lock));
    free(q->items);
    free(q);
}

int queue_push(struct event_queue *q, const struct event *ev)
{
    CHECK_PTHREAD(pthread_mutex_lock(&q->lock));
    while (q->count == q->capacity && !q->closed)
        CHECK_PTHREAD(pthread_cond_wait(&q->not_full, &q->lock));

    int rc = -1;
    if (!q->closed) {
        q->items[(q->head + q->count) % q->capacity] = *ev;
        q->count++;
        CHECK_PTHREAD(pthread_cond_signal(&q->not_empty));
        rc = 0;
    }
    CHECK_PTHREAD(pthread_mutex_unlock(&q->lock));
    return rc;
}

int queue_pop(struct event_queue *q, struct event *out)
{
    CHECK_PTHREAD(pthread_mutex_lock(&q->lock));
    while (q->count == 0 && !q->closed)
        CHECK_PTHREAD(pthread_cond_wait(&q->not_empty, &q->lock));

    int rc = -1;
    if (q->count > 0) {
        *out = q->items[q->head];
        q->head = (q->head + 1) % q->capacity;
        q->count--;
        CHECK_PTHREAD(pthread_cond_signal(&q->not_full));
        rc = 0;
    }
    CHECK_PTHREAD(pthread_mutex_unlock(&q->lock));
    return rc;
}

void queue_close(struct event_queue *q)
{
    CHECK_PTHREAD(pthread_mutex_lock(&q->lock));
    q->closed = true;
    CHECK_PTHREAD(pthread_cond_broadcast(&q->not_empty));
    CHECK_PTHREAD(pthread_cond_broadcast(&q->not_full));
    CHECK_PTHREAD(pthread_mutex_unlock(&q->lock));
}

void queue_sink(const struct event *ev, void *queue)
{
    if (queue_push(queue, ev) != 0)
        LOG_WARN("queue is closed, dropped %s event from %.*s",
                 event_type_name(ev->type), EV_IP_LEN - 1, ev->src_ip);
}
