#define _DEFAULT_SOURCE
#include "ids/capture.h"
#include <pcap/pcap.h>
#include "core/log.h"

long capture_read_file(const char *path)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_open_offline(path, errbuf);
    if (p == NULL) {
        LOG_ERROR("cannot open '%s': %s", path, errbuf);
        return -1;
    }

    long count = 0;
    struct pcap_pkthdr *hdr;
    const u_char *data;
    int rc;
    while ((rc = pcap_next_ex(p, &hdr, &data)) == 1)
        count++;

    if (rc == PCAP_ERROR) {
        LOG_ERROR("error reading '%s': %s", path, pcap_geterr(p));
        count = -1;
    }

    pcap_close(p);
    return count;
}