#include "honeypot.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "auth.h"
#include "core/event.h"
#include "core/log.h"
#include "fakeshell.h"
#include "net.h"
#include "session.h"

#define HP_LINE 256   /* максимальна довжина рядка від атакера */

/* створити сервер-сокет на заданому порту; -1 при помилці */
static int make_server(int port)
{
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        LOG_ERROR("socket: %s", strerror(errno));
        return -1;
    }

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (bind(srv, (struct sockaddr *)&addr, sizeof addr) != 0) {
        LOG_ERROR("bind port %d: %s", port, strerror(errno));
        close(srv);
        return -1;
    }
    if (listen(srv, 16) != 0) {
        LOG_ERROR("listen: %s", strerror(errno));
        close(srv);
        return -1;
    }

    /* accept із таймаутом: щоб періодично перевіряти прапорець зупинки */
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(srv, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    return srv;
}

/* повна сесія ОДНОГО атакера: вхід -> фейкова консоль */
static void run_session(struct hp_session *s)
{
    char line[HP_LINE];
    char user[EV_USER_LEN] = "";

    struct event hello = hp_event(s, EV_CONNECT);
    hp_emit(s, &hello);

    /* --- етап входу --- */
    struct auth_state st = { 0 };
    while (!st.authenticated) {
        net_send(s->conn, "login: ");
        if (net_read_line(s->conn, line, sizeof line) <= 0)
            goto done;
        event_set_str(user, sizeof user, line);

        net_send(s->conn, "password: ");
        if (net_read_line(s->conn, line, sizeof line) <= 0)
            goto done;

        if (!auth_try(&st, s, user, line))
            net_send(s->conn, "Permission denied\r\n");
    }

    /* --- фейкова консоль --- */
    net_send(s->conn, "Welcome to Ubuntu 22.04.3 LTS\r\n");
    for (;;) {
        net_send(s->conn, "$ ");
        if (net_read_line(s->conn, line, sizeof line) <= 0)
            break;
        if (strcmp(line, "exit") == 0 || strcmp(line, "logout") == 0)
            break;
        shell_exec(s, line);
    }

done:
    {
        struct event bye = hp_event(s, EV_DISCONNECT);
        hp_emit(s, &bye);
    }
    close(s->conn);
}

/* аргумент потоку: сесія + лічильник активних клієнтів */
struct client_arg {
    struct hp_session sess;
    atomic_int       *live;
};

static void *client_thread(void *arg)
{
    struct client_arg *c = arg;
    run_session(&c->sess);
    atomic_fetch_sub(c->live, 1);
    free(c);
    return NULL;
}

void honeypot_run(int port, int login_after, int max_clients,
                  event_sink_fn sink, void *ctx,
                  const volatile sig_atomic_t *stop)
{
    int srv = make_server(port);
    if (srv < 0)
        return;
    LOG_INFO("honeypot listening on port %d", port);

    atomic_int live = 0;
    uint32_t next_sid = 1;

    while (!*stop) {
        struct sockaddr_in cli;
        socklen_t len = sizeof cli;
        int conn = accept(srv, (struct sockaddr *)&cli, &len);
        if (conn < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                continue;              /* таймаут/сигнал -> перевіряємо stop */
            LOG_ERROR("accept: %s", strerror(errno));
            continue;
        }
        /* зняти успадкований від слухача таймаут, інакше читання від
           атакера рветься за 1 секунду (та сама timeval, що в make_server) */
        struct timeval no_to = { .tv_sec = 0, .tv_usec = 0 };
        setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, &no_to, sizeof no_to);
        if (atomic_load(&live) >= max_clients) {
            net_send(conn, "Too many connections\r\n");
            close(conn);
            continue;
        }

        struct client_arg *c = calloc(1, sizeof *c);
        if (!c) {
            close(conn);
            continue;
        }
        c->sess.conn = conn;
        c->sess.port = (uint16_t)port;
        c->sess.sid = next_sid++;
        c->sess.login_after = login_after;
        c->sess.sink = sink;
        c->sess.ctx = ctx;
        inet_ntop(AF_INET, &cli.sin_addr, c->sess.ip, sizeof c->sess.ip);
        c->live = &live;

        LOG_INFO("connection from %s (session %u)", c->sess.ip, c->sess.sid);
        atomic_fetch_add(&live, 1);

        pthread_t t;
        if (pthread_create(&t, NULL, client_thread, c) != 0) {
            LOG_ERROR("pthread_create: %s", strerror(errno));
            atomic_fetch_sub(&live, 1);
            close(conn);
            free(c);
            continue;
        }
        pthread_detach(t);  /* потік сам прибереться після завершення */
    }

    close(srv);
    LOG_INFO("honeypot stopped");
}