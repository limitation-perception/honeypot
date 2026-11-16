#ifndef IDS_CAPTURE_H
#define IDS_CAPTURE_H

struct capture_stats {
    long packets;
    long ipv4;
    long bad;
};

int capture_read_file(const char *path, struct capture_stats *stats);

#endif