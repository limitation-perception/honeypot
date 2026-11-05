#ifndef HONEYPOT_NET_H
#define HONEYPOT_NET_H

#include <stddef.h>

/* відправити рядок клієнту */
void net_send(int conn, const char *s);

/* прочитати один рядок (до Enter). прибирає \r і \n, завжди ставить '\0'.
   читає не більше size-1 байтів - захист від переповнення буфера.
   повертає: >0 прочитано байтів, 0 клієнт від'єднався, <0 помилка. */
int net_read_line(int conn, char *buf, size_t size);

#endif