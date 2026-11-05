#ifndef HONEYPOT_HONEYPOT_H
#define HONEYPOT_HONEYPOT_H

#include <signal.h>

#include "core/event.h"

/* сюди Соня підставить запис у чергу */
typedef void (*event_sink_fn)(const struct event *ev, void *ctx);

/* запустити honeypot, слухає TCP-порт і обробляє атакерів, доки *stop == 0. */

void honeypot_run(int port, int login_after, int max_clients,
                  event_sink_fn sink, void *ctx,
                  const volatile sig_atomic_t *stop);

#endif