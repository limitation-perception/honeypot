#ifndef HONEYPOT_SESSION_H
#define HONEYPOT_SESSION_H

#include <stdint.h>

#include "core/event.h"
#include "honeypot.h"

/* контекст однієї сесії атакера */
struct hp_session {
    int           conn;            /* сокет з'єднання */
    char          ip[EV_IP_LEN];   /* IP атакера */
    uint16_t      port;            /* порт honeypot (йде в dst_port) */
    uint32_t      sid;             /* номер сесії */
    int           login_after;     /* впустити після N спроб */
    event_sink_fn sink;            /* куди віддавати події */
    void         *ctx;
};

/* заготовити подію з уже заповненою базою (тип, джерело=honeypot, час, IP, порт, номер сесії) */
static inline struct event hp_event(const struct hp_session *s, event_type_t type)
{
    struct event ev;
    event_init(&ev, type, EV_SOURCE_HONEYPOT, s->ip);
    ev.dst_port = s->port;
    ev.session_id = s->sid;
    return ev;
}

/* віддати подію через sink (якщо він заданий) */
static inline void hp_emit(const struct hp_session *s, const struct event *ev)
{
    if (s->sink)
        s->sink(ev, s->ctx);
}

#endif