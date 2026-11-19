#include "ids/detectors.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

#define FLOOD_TOP_SOURCES 8

struct src_count {
    uint32_t ip;
    int      n;
};

struct flood_tracker {
    bool     used;
    uint32_t ip;
    uint16_t port;
    int64_t  last_us;
    int64_t  win_start;
    int      count;
    bool     alerted;
    int      nsrc;
    bool     more_src;
    struct src_count src[FLOOD_TOP_SOURCES];
};

struct arp_entry {
    bool     used;
    uint32_t ip;
    uint8_t  mac[MAC_LEN];
    int64_t  last_us;
    bool     alerted;
    uint8_t  alert_mac[MAC_LEN];
    int64_t  alert_us;
};

struct detectors {
    struct ids_thresholds th;
    int64_t scan_window_us;
    int64_t flood_window_us;
    ids_sink_fn sink;
    void *ctx;
    struct scan_tracker scans[MAX_TRACKED];
    struct flood_tracker floods[MAX_TRACKED];
    struct arp_entry arps[MAX_TRACKED];
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
    d->flood_window_us = th->synflood_window_sec * US_PER_SEC;
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

static struct flood_tracker *find_flood_tracker(struct detectors *d, uint32_t ip,
                                                uint16_t port, int64_t now)
{
    struct flood_tracker *victim = &d->floods[0];

    for (int i = 0; i < MAX_TRACKED; i++) {
        struct flood_tracker *t = &d->floods[i];
        if (t->used && t->ip == ip && t->port == port)
            return t;
        if (!t->used) {
            if (victim->used)
                victim = t;
        } else if (victim->used && t->last_us < victim->last_us) {
            victim = t;
        }
    }

    memset(victim, 0, sizeof *victim);
    victim->used = true;
    victim->ip = ip;
    victim->port = port;
    victim->win_start = now;
    return victim;
}

static void count_source(struct flood_tracker *t, uint32_t ip)
{
    for (int i = 0; i < t->nsrc; i++) {
        if (t->src[i].ip == ip) {
            t->src[i].n++;
            return;
        }
    }
    if (t->nsrc < FLOOD_TOP_SOURCES) {
        t->src[t->nsrc].ip = ip;
        t->src[t->nsrc].n = 1;
        t->nsrc++;
    } else {
        t->more_src = true;
    }
}

static void report_flood(struct detectors *d, struct flood_tracker *t, int64_t now)
{
    int top = 0;
    for (int i = 1; i < t->nsrc; i++)
        if (t->src[i].n > t->src[top].n)
            top = i;

    char src[EV_IP_LEN];
    char victim[EV_IP_LEN];
    ipv4_to_str(t->src[top].ip, src, sizeof src);
    ipv4_to_str(t->ip, victim, sizeof victim);

    struct event ev;
    event_init(&ev, EV_SYN_FLOOD, EV_SOURCE_IDS, src);
    ev.timestamp = (time_t)(now / US_PER_SEC);
    ev.dst_port = t->port;
    snprintf(ev.details, sizeof ev.details, "%d SYN to %s:%u in %ds from %d%s source%s%s",
             t->count, victim, t->port, d->th.synflood_window_sec,
             t->nsrc, t->more_src ? "+" : "",
             (t->nsrc == 1 && !t->more_src) ? "" : "s",
             t->more_src ? " (spoofed?)" : "");

    d->sink(&ev, d->ctx);
}

static void detect_syn_flood(struct detectors *d, const struct packet *p, int64_t now)
{
    if (!p->has_tcp || (p->tcp_flags & (TCP_SYN | TCP_ACK)) != TCP_SYN)
        return;

    struct flood_tracker *t = find_flood_tracker(d, p->ip_dst, p->dst_port, now);

    if (now - t->win_start >= d->flood_window_us) {
        if (t->count < d->th.synflood_syns || now - t->win_start >= 2 * d->flood_window_us)
            t->alerted = false;
        t->win_start = now;
        t->count = 0;
        t->nsrc = 0;
        t->more_src = false;
    }

    t->last_us = now;
    t->count++;
    count_source(t, p->ip_src);

    if (!t->alerted && t->count >= d->th.synflood_syns) {
        report_flood(d, t, now);
        t->alerted = true;
    }
}

static struct arp_entry *find_arp_entry(struct detectors *d, uint32_t ip, bool *is_new)
{
    struct arp_entry *victim = &d->arps[0];

    for (int i = 0; i < MAX_TRACKED; i++) {
        struct arp_entry *e = &d->arps[i];
        if (e->used && e->ip == ip) {
            *is_new = false;
            return e;
        }
        if (!e->used) {
            if (victim->used)
                victim = e;
        } else if (victim->used && e->last_us < victim->last_us) {
            victim = e;
        }
    }

    memset(victim, 0, sizeof *victim);
    victim->used = true;
    victim->ip = ip;
    *is_new = true;
    return victim;
}

static bool find_ip_by_mac(const struct detectors *d, const uint8_t mac[MAC_LEN],
                           uint32_t except_ip, uint32_t *out)
{
    for (int i = 0; i < MAX_TRACKED; i++) {
        const struct arp_entry *e = &d->arps[i];
        if (e->used && e->ip != except_ip && memcmp(e->mac, mac, MAC_LEN) == 0) {
            *out = e->ip;
            return true;
        }
    }
    return false;
}

static void report_arp_spoof(struct detectors *d, const struct arp_entry *e,
                             const struct packet *p, int64_t now)
{
    char ip[EV_IP_LEN];
    char old_mac[MAC_STR_LEN];
    char new_mac[MAC_STR_LEN];
    ipv4_to_str(p->arp_spa, ip, sizeof ip);
    mac_to_str(e->mac, old_mac, sizeof old_mac);
    mac_to_str(p->arp_sha, new_mac, sizeof new_mac);

    uint32_t attacker = p->arp_spa;
    char owner[EV_IP_LEN] = "unknown";
    if (find_ip_by_mac(d, p->arp_sha, p->arp_spa, &attacker))
        ipv4_to_str(attacker, owner, sizeof owner);

    char src[EV_IP_LEN];
    ipv4_to_str(attacker, src, sizeof src);

    struct event ev;
    event_init(&ev, EV_ARP_SPOOF, EV_SOURCE_IDS, src);
    ev.timestamp = (time_t)(now / US_PER_SEC);
    snprintf(ev.details, sizeof ev.details, "%s is-at %s (was %s), MAC owner: %s",
             ip, new_mac, old_mac, owner);

    d->sink(&ev, d->ctx);
}

static void detect_arp_spoof(struct detectors *d, const struct packet *p, int64_t now)
{
    if (!p->has_arp)
        return;
    if (p->arp_spa == 0)
        return;

    bool is_new;
    struct arp_entry *e = find_arp_entry(d, p->arp_spa, &is_new);
    e->last_us = now;

    if (is_new) {
        memcpy(e->mac, p->arp_sha, MAC_LEN);
        return;
    }
    if (memcmp(e->mac, p->arp_sha, MAC_LEN) == 0)
        return;

    if (e->alerted && memcmp(e->alert_mac, p->arp_sha, MAC_LEN) == 0 &&
        now - e->alert_us < IDS_ARP_REALERT_SEC * US_PER_SEC)
        return;

    report_arp_spoof(d, e, p, now);
    memcpy(e->alert_mac, p->arp_sha, MAC_LEN);
    e->alert_us = now;
    e->alerted = true;
}

void detectors_feed(struct detectors *d, const struct packet *pkt, int64_t ts_us)
{
    detect_port_scan(d, pkt, ts_us);
    detect_syn_flood(d, pkt, ts_us);
    detect_arp_spoof(d, pkt, ts_us);
}