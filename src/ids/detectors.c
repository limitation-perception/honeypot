#include "ids/detectors.h"

#include <stdlib.h>

struct detectors {
    struct ids_thresholds th;
    ids_sink_fn sink;
    void *ctx;
};

struct detectors *detectors_create(const struct ids_thresholds *th,
                                   ids_sink_fn sink, void *ctx)
{
    if (th == NULL || sink == NULL)
        return NULL;
    if (th->portscan_ports <= 0 || th->portscan_window_sec <= 0 ||
        th->synflood_syns <= 0 || th->synflood_window_sec <= 0)
        return NULL;

    struct detectors *d = calloc(1, sizeof *d);
    if (d == NULL)
        return NULL;

    d->th = *th;
    d->sink = sink;
    d->ctx = ctx;
    return d;
}

void detectors_destroy(struct detectors *d)
{
    free(d);
}

void detectors_feed(struct detectors *d, const struct packet *pkt, int64_t ts_us)
{
    (void)d;
    (void)pkt;
    (void)ts_us;
}