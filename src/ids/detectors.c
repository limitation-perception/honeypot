#include "ids/detectors.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#define US_PER_SEC 1000000LL


#define MAX_TRACKED 256

struct probe {
    uint16_t port;
    int64_t  t_us;
};

struct scan_tracker {
    bool          used;
    uint32_t      ip;
    int64_t       last_us;
    bool          alerted;
    uint32_t      last_dst;
    int           nprobes;
    struct probe *probes;
};

struct detectors {
    struct ids_thresholds th;
    int64_t scan_window_us;
    ids_sink_fn sink;
    void *ctx;
    struct scan_tracker scans[MAX_TRACKED];
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
    d->scan_window_us = th->portscan_window_sec * US_PER_SEC;
    d->sink = sink;
    d->ctx = ctx;
    return d;
}

void detectors_destroy(struct detectors *d)
{
    if (d == NULL)
        return;
    for (int i = 0; i < MAX_TRACKED; i++)
        free(d->scans[i].probes);
    free(d);
}

static struct scan_tracker *find_scan_tracker(struct detectors *d, uint32_t ip, int64_t now)
{
    struct scan_tracker *victim = &d->scans[0];

    for (int i = 0; i < MAX_TRACKED; i++) {
        struct scan_tracker *t = &d->scans[i];
        if (t->used && t->ip == ip)
            return t;
        if (!t->used) {
            if (victim->used)
                victim = t;
        } else if (victim->used && t->last_us < victim->last_us) {
            victim = t;
        }
    }

    if (victim->probes == NULL) {
        victim->probes = calloc((size_t)d->th.portscan_ports, sizeof *victim->probes);
        if (victim->probes == NULL)
            return NULL;
    }
    victim->used = true;
    victim->ip = ip;
    victim->last_us = now;
    victim->alerted = false;
    victim->nprobes = 0;
    return victim;
}

static bool is_scan_probe(const struct packet *p)
{
    return p->has_tcp && !(p->tcp_flags & (TCP_ACK | TCP_RST));
}

static bool update_probes(struct scan_tracker *t, uint16_t port, int64_t now, int64_t window)
{
    bool seen = false;
    int keep = 0;
    for (int i = 0; i < t->nprobes; i++) {
        if (now - t->probes[i].t_us > window)
            continue;
        if (t->probes[i].port == port) {
            t->probes[i].t_us = now;
            seen = true;
        }
        t->probes[keep] = t->probes[i];
        keep++;
    }
    t->nprobes = keep;
    return seen;
}

static void report_scan(struct detectors *d, struct scan_tracker *t, int64_t now)
{
    int64_t first = now;
    for (int i = 0; i < t->nprobes; i++)
        if (t->probes[i].t_us < first)
            first = t->probes[i].t_us;

    char src[EV_IP_LEN];
    char dst[EV_IP_LEN];
    ipv4_to_str(t->ip, src, sizeof src);
    ipv4_to_str(t->last_dst, dst, sizeof dst);

    struct event ev;
    event_init(&ev, EV_PORT_SCAN, EV_SOURCE_IDS, src);
    ev.timestamp = (time_t)(now / US_PER_SEC);
    snprintf(ev.details, sizeof ev.details, "%d ports in %.1fs to %s",
             t->nprobes, (double)(now - first) / US_PER_SEC, dst);

    d->sink(&ev, d->ctx);
}

static void detect_port_scan(struct detectors *d, const struct packet *p, int64_t now)
{
    if (!is_scan_probe(p))
        return;

    struct scan_tracker *t = find_scan_tracker(d, p->ip_src, now);
    if (t == NULL)
        return;

    if (now - t->last_us > d->scan_window_us) {
        t->alerted = false;
        t->nprobes = 0;
    }
    t->last_us = now;
    t->last_dst = p->ip_dst;

    if (t->alerted)
        return;

    bool seen = update_probes(t, p->dst_port, now, d->scan_window_us);
    if (!seen) {
        t->probes[t->nprobes].port = p->dst_port;
        t->probes[t->nprobes].t_us = now;
        t->nprobes++;
    }

    if (t->nprobes >= d->th.portscan_ports) {
        report_scan(d, t, now);
        t->alerted = true;
        t->nprobes = 0;
    }
}

void detectors_feed(struct detectors *d, const struct packet *pkt, int64_t ts_us)
{
    detect_port_scan(d, pkt, ts_us);
}