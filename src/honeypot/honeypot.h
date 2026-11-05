#ifndef HONEYPOT_HONEYPOT_H
#define HONEYPOT_HONEYPOT_H

#include <signal.h>

#include "core/event.h"

/* сюди Соня підставить запис у чергу */
typedef void (*event_sink_fn)(const struct event *ev, void *ctx);

/* Запустити honeypot: слухати TCP-порт і обробляти атакерів, доки *stop == 0.
   Функція БЛОКУЄ потік (цикл accept), тому Роль 3 запускає її в окремому
   pthread (етап 5). Кожен атакер обробляється у власному потоці.   */

void honeypot_run(int port, int login_after, int max_clients,
                  event_sink_fn sink, void *ctx,
                  const volatile sig_atomic_t *stop);

#endif