#ifndef CORE_CORRELATOR_H
#define CORE_CORRELATOR_H

#include <stdio.h>

#include "core/event.h"
#include "core/incident.h"
#include "core/queue.h"
#include "storage/db.h"

struct correlator;

struct correlator *correlator_create(struct db *db, FILE *alerts, int incident_timeout_sec);
void correlator_destroy(struct correlator *c);

int  correlator_process(struct correlator *c, const struct event *ev);
void correlator_run(struct correlator *c, struct event_queue *q);

const struct incident *correlator_incident(const struct correlator *c, const char *src_ip);

#endif
