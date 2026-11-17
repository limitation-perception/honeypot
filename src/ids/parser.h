#ifndef IDS_PARSER_H
#define IDS_PARSER_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MAC_LEN 6
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP  0x0806
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17

struct packet {
    uint8_t  eth_dst[MAC_LEN];
    uint8_t  eth_src[MAC_LEN];
    uint16_t ethertype;

    bool     has_ipv4;
    uint32_t ip_src;
    uint32_t ip_dst;
    uint8_t  ip_proto;
};

int parse_ethernet(const uint8_t *data, size_t len, struct packet *out);

void ipv4_to_str(uint32_t ip, char *buf, size_t size);

#endif