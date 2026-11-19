#define _DEFAULT_SOURCE

#include "ids/capture.h"
#include <string.h>
#include <pcap/pcap.h>
#include "core/log.h"
#include "ids/parser.h"

#define SNAPLEN    256
#define TIMEOUT_MS 500

static int set_filter(pcap_t *p)
{
    struct bpf_program prog;
    if (pcap_compile(p, &prog, IDS_BPF_FILTER, 1, PCAP_NETMASK_UNKNOWN) != 0) {
        LOG_ERROR("pcap_compile: %s", pcap_geterr(p));
        return -1;
    }
    int rc = pcap_setfilter(p, &prog);
    pcap_freecode(&prog);
    if (rc != 0) {
        LOG_ERROR("pcap_setfilter: %s", pcap_geterr(p));
        return -1;
    }
    return 0;
}

static int run(pcap_t *p, const struct ids_thresholds *th, ids_sink_fn sink, void *ctx,
               const volatile sig_atomic_t *stop, struct capture_stats *stats)
{
    memset(stats, 0, sizeof *stats);

    if (pcap_datalink(p) != DLT_EN10MB) {
        LOG_ERROR("only Ethernet is supported, got link type %s",
                  pcap_datalink_val_to_name(pcap_datalink(p)));
        return -1;
    }
    if (set_filter(p) != 0)
        return -1;

    struct detectors *det = detectors_create(th, sink, ctx);
    if (det == NULL) {
        LOG_ERROR("cannot create detectors (bad thresholds or out of memory)");
        return -1;
    }

    struct pcap_pkthdr *hdr;
    const u_char *data;
    int rc = 0;
    while (stop == NULL || !*stop) {
        rc = pcap_next_ex(p, &hdr, &data);
        if (rc == 0)
            continue;
        if (rc != 1)
            break;

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
        LOG_ERROR("capture error: %s", pcap_geterr(p));
        result = -1;
    }

    detectors_destroy(det);
    return result;
}

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

    int rc = run(p, th, sink, ctx, NULL, stats);
    pcap_close(p);
    return rc;
}

int capture_live(const char *ifname, const struct ids_thresholds *th,
                 ids_sink_fn sink, void *ctx, const volatile sig_atomic_t *stop,
                 struct capture_stats *stats)
{
    memset(stats, 0, sizeof *stats);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_create(ifname, errbuf);
    if (p == NULL) {
        LOG_ERROR("pcap_create(%s): %s", ifname, errbuf);
        return -1;
    }
    pcap_set_snaplen(p, SNAPLEN);
    pcap_set_promisc(p, 1);
    pcap_set_timeout(p, TIMEOUT_MS);
    pcap_set_immediate_mode(p, 1);

    int rc = pcap_activate(p);
    if (rc < 0) {
        LOG_ERROR("cannot capture on '%s': %s", ifname, pcap_geterr(p));
        if (rc == PCAP_ERROR_PERM_DENIED)
            LOG_ERROR("run as root or: sudo setcap cap_net_raw,cap_net_admin=eip build/honeytrap");
        else if (rc == PCAP_ERROR_NO_SUCH_DEVICE)
            LOG_ERROR("no such interface, see `ip link`");
        pcap_close(p);
        return -1;
    }
    if (rc > 0)
        LOG_WARN("pcap_activate(%s): %s", ifname, pcap_geterr(p));

    LOG_INFO("IDS listening on %s", ifname);
    rc = run(p, th, sink, ctx, stop, stats);
    pcap_close(p);
    return rc;
}