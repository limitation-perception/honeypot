#include "ids/parser.h"
#include <string.h>
#include <arpa/inet.h>

struct eth_hdr {
    uint8_t  dst[MAC_LEN];
    uint8_t  src[MAC_LEN];
    uint16_t type;
};

_Static_assert(sizeof(struct eth_hdr) == 14, "eth_hdr must be exactly 14 bytes");

int parse_ethernet(const uint8_t *data, size_t len, struct packet *out)
{
    memset(out, 0, sizeof *out);

    struct eth_hdr eth;
    if (len < sizeof eth)
        return -1;
    memcpy(&eth, data, sizeof eth);

    memcpy(out->eth_dst, eth.dst, MAC_LEN);
    memcpy(out->eth_src, eth.src, MAC_LEN);
    out->ethertype = ntohs(eth.type);
    return 0;
}