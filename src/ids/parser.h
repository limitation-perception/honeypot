#ifndef IDS_PARSER_H
#define IDS_PARSER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MAC_LEN 6
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP  0x0806
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

struct packet {
    uint8_t  eth_dst[MAC_LEN];
    uint8_t  eth_src[MAC_LEN];
    uint16_t ethertype;

    bool     has_ipv4;
    uint32_t ip_src;
    uint32_t ip_dst;
    uint8_t  ip_proto;

    bool     has_tcp;
    bool     has_udp;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  tcp_flags;
    
    bool     has_arp;
    uint16_t arp_op;
    uint8_t  arp_sha[MAC_LEN];
    uint32_t arp_spa;
    uint32_t arp_tpa;
};

int parse_ethernet(const uint8_t *data, size_t len, struct packet *out);

void ipv4_to_str(uint32_t ip, char *buf, size_t size);

#endif