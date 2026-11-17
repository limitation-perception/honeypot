#include "ids/parser.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

struct eth_hdr {
    uint8_t  dst[MAC_LEN];
    uint8_t  src[MAC_LEN];
    uint16_t type;
};

struct ipv4_hdr {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
};

_Static_assert(sizeof(struct eth_hdr) == 14, "eth_hdr must be exactly 14 bytes");
_Static_assert(sizeof(struct ipv4_hdr) == 20, "ipv4_hdr must be exactly 20 bytes");

static int parse_ipv4(const uint8_t *data, size_t len, struct packet *out)
{
    struct ipv4_hdr ip;
    if (len < sizeof ip)
        return -1;
    memcpy(&ip, data, sizeof ip);

    unsigned version = ip.ver_ihl >> 4;
    size_t hdr_len = (size_t)(ip.ver_ihl & 0x0F) * 4;
    if (version != 4 || hdr_len < sizeof ip || hdr_len > len)
        return -1;

    out->ip_src = ntohl(ip.src);
    out->ip_dst = ntohl(ip.dst);
    out->ip_proto = ip.proto;
    out->has_ipv4 = true;
    return 0;
}

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

    if (out->ethertype == ETHERTYPE_IPV4)
        return parse_ipv4(data + sizeof eth, len - sizeof eth, out);
    return 0;
}

void ipv4_to_str(uint32_t ip, char *buf, size_t size)
{
    snprintf(buf, size, "%u.%u.%u.%u",
             (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}