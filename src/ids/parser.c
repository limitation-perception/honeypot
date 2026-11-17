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

struct tcp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_off;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
};

struct udp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

_Static_assert(sizeof(struct eth_hdr) == 14, "eth_hdr must be exactly 14 bytes");
_Static_assert(sizeof(struct ipv4_hdr) == 20, "ipv4_hdr must be exactly 20 bytes");
_Static_assert(sizeof(struct tcp_hdr) == 20, "tcp_hdr must be exactly 20 bytes");
_Static_assert(sizeof(struct udp_hdr) == 8, "udp_hdr must be exactly 8 bytes");

#define IP_FRAG_OFFSET_MASK 0x1FFF

static int parse_tcp(const uint8_t *data, size_t len, struct packet *out)
{
    struct tcp_hdr tcp;
    if (len < sizeof tcp)
        return -1;
    memcpy(&tcp, data, sizeof tcp);

    size_t hdr_len = (size_t)(tcp.data_off >> 4) * 4;
    if (hdr_len < sizeof tcp)
        return -1;

    out->src_port = ntohs(tcp.src_port);
    out->dst_port = ntohs(tcp.dst_port);
    out->tcp_flags = tcp.flags;
    out->has_tcp = true;
    return 0;
}

static int parse_udp(const uint8_t *data, size_t len, struct packet *out)
{
    struct udp_hdr udp;
    if (len < sizeof udp)
        return -1;
    memcpy(&udp, data, sizeof udp);

    out->src_port = ntohs(udp.src_port);
    out->dst_port = ntohs(udp.dst_port);
    out->has_udp = true;
    return 0;
}

static int parse_ipv4(const uint8_t *data, size_t len, struct packet *out)
{
    struct ipv4_hdr ip;
    if (len < sizeof ip)
        return -1;
    memcpy(&ip, data, sizeof ip);

    unsigned version = ip.ver_ihl >> 4;
    size_t hdr_len = (size_t)(ip.ver_ihl & 0x0F) * 4;
    size_t total_len = ntohs(ip.total_len);
    if (version != 4 || hdr_len < sizeof ip || hdr_len > len || total_len < hdr_len)
        return -1;

    out->ip_src = ntohl(ip.src);
    out->ip_dst = ntohl(ip.dst);
    out->ip_proto = ip.proto;
    out->has_ipv4 = true;

    if ((ntohs(ip.frag) & IP_FRAG_OFFSET_MASK) != 0)
        return 0;

    size_t avail = total_len < len ? total_len : len;
    const uint8_t *payload = data + hdr_len;
    size_t payload_len = avail - hdr_len;

    if (ip.proto == IP_PROTO_TCP)
        return parse_tcp(payload, payload_len, out);
    if (ip.proto == IP_PROTO_UDP)
        return parse_udp(payload, payload_len, out);
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