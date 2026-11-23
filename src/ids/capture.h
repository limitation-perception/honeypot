#ifndef IDS_CAPTURE_H
#define IDS_CAPTURE_H

#include <signal.h>
#include "ids/detectors.h"


#define IDS_BPF_FILTER "arp or (tcp and tcp[tcpflags] & tcp-ack == 0)"

struct capture_stats {
    long packets;
    long ipv4;
    long syn;
    long bad;
};

int capture_read_file(const char *path, const struct ids_thresholds *th,
                      ids_sink_fn sink, void *ctx, struct capture_stats *stats);

int capture_live(const char *ifname, const struct ids_thresholds *th,
                 ids_sink_fn sink, void *ctx, const volatile sig_atomic_t *stop,
                 struct capture_stats *stats);

#endif