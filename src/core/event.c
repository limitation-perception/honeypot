#include "core/event.h"

#include <stdio.h>
#include <string.h>

static const char *const type_names[] = {
    [EV_PORT_SCAN]        = "PORT_SCAN",
    [EV_SYN_FLOOD]        = "SYN_FLOOD",
    [EV_ARP_SPOOF]        = "ARP_SPOOF",
    [EV_CONNECT]          = "CONNECT",
    [EV_LOGIN_ATTEMPT]    = "LOGIN_ATTEMPT",
    [EV_LOGIN_SUCCESS]    = "LOGIN_SUCCESS",
    [EV_COMMAND]          = "COMMAND",
    [EV_DOWNLOAD_ATTEMPT] = "DOWNLOAD_ATTEMPT",
    [EV_DISCONNECT]       = "DISCONNECT",
};

_Static_assert(sizeof type_names / sizeof type_names[0] == EV_TYPE_COUNT,
               "type_names must have a name for every event_type_t");

void event_init(struct event *ev, event_type_t type, event_source_t source,
                const char *src_ip)
{
    memset(ev, 0, sizeof *ev);
    ev->type = type;
    ev->source = source;
    ev->timestamp = time(NULL);
    event_set_str(ev->src_ip, sizeof ev->src_ip, src_ip);
}

void event_set_str(char *dst, size_t dst_size, const char *src)
{
    snprintf(dst, dst_size, "%s", src ? src : "");
}

const char *event_type_name(event_type_t type)
{
    if ((unsigned)type >= EV_TYPE_COUNT)
        return "UNKNOWN";
    return type_names[type];
}
