#define _DEFAULT_SOURCE

#include "ids/capture.h"

#include <string.h>

#include <pcap/pcap.h>

#include "core/log.h"
#include "ids/parser.h"

int capture_read_file(const char *path, const struct ids_thresholds *th,
                      ids_sink_fn sink, void *ctx, struct capture_stats *stats)
{
    memset(stats, 0, sizeof *stats);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_open_offline(path, errbuf);
    if (p == NULL) {
        LOG_ERROR("cannot open '%s': %s", path, errbuf);
        return -1;
    }

    struct detectors *det = detectors_create(th, sink, ctx);
    if (det == NULL) {
        LOG_ERROR("cannot create detectors (bad thresholds or out of memory)");
        pcap_close(p);
        return -1;
    }

    struct pcap_pkthdr *hdr;
    const u_char *data;
    int rc;
    while ((rc = pcap_next_ex(p, &hdr, &data)) == 1) {
        stats->packets++;

        struct packet pkt;
        if (parse_ethernet(data, hdr->caplen, &pkt) != 0) {
            stats->bad++;
            continue;
        }
        if (pkt.has_ipv4)
            stats->ipv4++;
        if (pkt.has_tcp && (pkt.tcp_flags & TCP_SYN) && !(pkt.tcp_flags & TCP_ACK))
            stats->syn++;

        int64_t ts_us = (int64_t)hdr->ts.tv_sec * 1000000 + hdr->ts.tv_usec;
        detectors_feed(det, &pkt, ts_us);
    }

    int result = 0;
    if (rc == PCAP_ERROR) {
        LOG_ERROR("error reading '%s': %s", path, pcap_geterr(p));
        result = -1;
    }

    detectors_destroy(det);
    pcap_close(p);
    return result;
}