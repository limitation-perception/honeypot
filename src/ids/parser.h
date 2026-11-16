#ifndef IDS_PARSER_H
#define IDS_PARSER_H
#include <stddef.h>
#include <stdint.h>

#define MAC_LEN 6
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP  0x0806

struct packet {
    uint8_t  eth_dst[MAC_LEN];
    uint8_t  eth_src[MAC_LEN];
    uint16_t ethertype;
};

int parse_ethernet(const uint8_t *data, size_t len, struct packet *out);

#endif