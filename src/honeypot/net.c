#include "net.h"

#include <string.h>
#include <sys/socket.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define TELNET_IAC 255   

void net_send(int conn, const char *s)
{
    send(conn, s, strlen(s), MSG_NOSIGNAL);
}

static int read_byte(int conn, unsigned char *c)
{
    return (int)recv(conn, c, 1, 0);
}

int net_read_line(int conn, char *buf, size_t size)
{
    size_t len = 0;
    unsigned char c;

    for (;;) {
        int r = read_byte(conn, &c);
        if (r <= 0)
            return r;                  

        if (c == '\n')
            break;                     

        if (c == TELNET_IAC) {         
            unsigned char skip;
            if (read_byte(conn, &skip) <= 0 || read_byte(conn, &skip) <= 0)
                return 0;
            continue;
        }

        if (c == '\r' || c == '\0')
            continue;                  

        if (len < size - 1)            
            buf[len++] = (char)c;
    }

    buf[len] = '\0';
    return 1;                          
}