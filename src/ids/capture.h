#ifndef IDS_CAPTURE_H
#define IDS_CAPTURE_H

#include "ids/detectors.h"

struct capture_stats {
    long packets;
    long ipv4;
    long syn;
    long bad;
};

int capture_read_file(const char *path, const struct ids_thresholds *th,
                      ids_sink_fn sink, void *ctx, struct capture_stats *stats);

#endif