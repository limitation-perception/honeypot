#ifndef IDS_DETECTORS_H
#define IDS_DETECTORS_H

#include <stdint.h>
#include "core/event.h"
#define IDS_ARP_REALERT_SEC 60
#include "ids/parser.h"

struct ids_thresholds {
    int portscan_ports;
    int portscan_window_sec;
    int synflood_syns;
    int synflood_window_sec;
};

typedef void (*ids_sink_fn)(const struct event *ev, void *ctx);

struct detectors;

struct detectors *detectors_create(const struct ids_thresholds *th,
                                   ids_sink_fn sink, void *ctx);

void detectors_destroy(struct detectors *d);

void detectors_feed(struct detectors *d, const struct packet *pkt, int64_t ts_us);

#endif