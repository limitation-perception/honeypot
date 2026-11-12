#ifndef CORE_QUEUE_H
#define CORE_QUEUE_H

#include <stddef.h>

#include "core/event.h"

struct event_queue;

struct event_queue *queue_create(size_t capacity);
void queue_destroy(struct event_queue *q);

int  queue_push(struct event_queue *q, const struct event *ev);
int  queue_pop(struct event_queue *q, struct event *out);
void queue_close(struct event_queue *q);

void queue_sink(const struct event *ev, void *queue);

#endif
