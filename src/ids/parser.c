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

struct arp_hdr {
    uint16_t htype;
    uint16_t ptype;
    uint8_t  hlen;
    uint8_t  plen;
    uint16_t op;
    uint8_t  sha[MAC_LEN];
    uint8_t  spa[4];
    uint8_t  tha[MAC_LEN];
    uint8_t  tpa[4];
};

_Static_assert(sizeof(struct eth_hdr) == 14, "eth_hdr must be exactly 14 bytes");
_Static_assert(sizeof(struct ipv4_hdr) == 20, "ipv4_hdr must be exactly 20 bytes");
_Static_assert(sizeof(struct tcp_hdr) == 20, "tcp_hdr must be exactly 20 bytes");
_Static_assert(sizeof(struct udp_hdr) == 8, "udp_hdr must be exactly 8 bytes");
_Static_assert(sizeof(struct arp_hdr) == 28, "arp_hdr must be exactly 28 bytes");

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

static uint32_t ip_from_bytes(const uint8_t b[4])
{
    return (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3];
}

static int parse_arp(const uint8_t *data, size_t len, struct packet *out)
{
    struct arp_hdr arp;
    if (len < sizeof arp)
        return -1;
    memcpy(&arp, data, sizeof arp);

    if (ntohs(arp.htype) != 1 || ntohs(arp.ptype) != ETHERTYPE_IPV4 ||
        arp.hlen != MAC_LEN || arp.plen != 4)
        return 0;

    out->arp_op = ntohs(arp.op);
    memcpy(out->arp_sha, arp.sha, MAC_LEN);
    out->arp_spa = ip_from_bytes(arp.spa);
    out->arp_tpa = ip_from_bytes(arp.tpa);
    out->has_arp = true;
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

    const uint8_t *payload = data + sizeof eth;
    size_t payload_len = len - sizeof eth;

    if (out->ethertype == ETHERTYPE_IPV4)
        return parse_ipv4(payload, payload_len, out);
    if (out->ethertype == ETHERTYPE_ARP)
        return parse_arp(payload, payload_len, out);
    return 0;
}

void ipv4_to_str(uint32_t ip, char *buf, size_t size)
{
    snprintf(buf, size, "%u.%u.%u.%u",
             (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}

void mac_to_str(const uint8_t mac[MAC_LEN], char *buf, size_t size)
{
    snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
