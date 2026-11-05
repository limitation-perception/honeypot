#include "net.h"

#include <string.h>
#include <sys/socket.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

void net_send(int conn, const char *s)
{
    send(conn, s, strlen(s), MSG_NOSIGNAL);
}

int net_read_line(int conn, char *buf, size_t size)
{
    ssize_t n = recv(conn, buf, size - 1, 0);  /* size-1: місце під '\0' */
    if (n <= 0)
        return (int)n;                         /* 0 = від'єднався, <0 = помилка */
    buf[n] = '\0';
    buf[strcspn(buf, "\r\n")] = '\0';          /* обрізати кінець рядка */
    return (int)n;
}