#ifndef HONEYPOT_NET_H
#define HONEYPOT_NET_H

#include <stddef.h>

void net_send(int conn, const char *s);

int net_read_line(int conn, char *buf, size_t size);

#endif