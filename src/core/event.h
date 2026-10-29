#ifndef CORE_EVENT_H
#define CORE_EVENT_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

typedef enum {
    EV_SOURCE_HONEYPOT,
    EV_SOURCE_IDS
} event_source_t;

typedef enum {
    EV_PORT_SCAN,
    EV_SYN_FLOOD,
    EV_ARP_SPOOF,
    EV_CONNECT,
    EV_LOGIN_ATTEMPT,
    EV_LOGIN_SUCCESS,
    EV_COMMAND,
    EV_DOWNLOAD_ATTEMPT,
    EV_DISCONNECT,
    EV_TYPE_COUNT
} event_type_t;

#define EV_IP_LEN       16
#define EV_USER_LEN     64
#define EV_PASS_LEN     64
#define EV_DETAILS_LEN 256

struct event {
    event_type_t   type;
    event_source_t source;
    time_t         timestamp;
    char           src_ip[EV_IP_LEN];
    uint16_t       dst_port;
    uint32_t       session_id;
    char           username[EV_USER_LEN];
    char           password[EV_PASS_LEN];
    char           details[EV_DETAILS_LEN];
};

void event_init(struct event *ev, event_type_t type, event_source_t source,
                const char *src_ip);

void event_set_str(char *dst, size_t dst_size, const char *src);

const char *event_type_name(event_type_t type);

#endif
