#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "core/correlator.h"
#include "core/log.h"
#include "core/queue.h"
#include "honeypot/honeypot.h"
#include "storage/db.h"
#include "storage/report.h"

static volatile sig_atomic_t g_stop = 0;

struct app {
    struct config       cfg;
    struct event_queue *queue;
    struct db          *db;
    struct correlator  *correlator;
    bool                honeypot_failed;
};

static struct app g_app;

static void on_signal(int sig)
{
    (void)sig;
    int saved_errno = errno;
    g_stop = 1;
    errno = saved_errno;
}

static void usage(const char *prog)
{
    fprintf(stderr, "usage: %s [-c config_file] [-r]\n"
                    "  -c  config file (default: %s)\n"
                    "  -r  only generate the report from the database and exit\n",
            prog, CONFIG_DEFAULT_PATH);
}

static int setup_signals(sigset_t *old_mask)
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &mask, old_mask) != 0) {
        LOG_ERROR("sigprocmask: %s", strerror(errno));
        return -1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) != 0 || sigaction(SIGTERM, &sa, NULL) != 0) {
        LOG_ERROR("sigaction: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static void *honeypot_thread(void *arg)
{
    struct app *app = arg;
    honeypot_run(app->cfg.honeypot_port, app->cfg.honeypot_login_after,
                 app->cfg.honeypot_max_clients, queue_sink, app->queue, &g_stop);
    if (!g_stop) {
        LOG_ERROR("honeypot stopped unexpectedly, shutting down");
        app->honeypot_failed = true;
        kill(getpid(), SIGTERM);
    }
    return NULL;
}

static void *correlator_thread(void *arg)
{
    struct app *app = arg;
    correlator_run(app->correlator, app->queue);
    return NULL;
}

static int run(struct app *app, const sigset_t *old_mask)
{
    app->db = db_open(app->cfg.storage_db_path);
    if (!app->db)
        return -1;
    app->queue = queue_create((size_t)app->cfg.core_queue_capacity);
    if (!app->queue)
        return -1;
    app->correlator = correlator_create(app->db, stdout, app->cfg.core_incident_timeout_sec);
    if (!app->correlator)
        return -1;

    pthread_t correlator_tid, honeypot_tid;
    int err = pthread_create(&correlator_tid, NULL, correlator_thread, app);
    if (err != 0) {
        LOG_ERROR("cannot start correlator thread: %s", strerror(err));
        return -1;
    }
    err = pthread_create(&honeypot_tid, NULL, honeypot_thread, app);
    if (err != 0) {
        LOG_ERROR("cannot start honeypot thread: %s", strerror(err));
        queue_close(app->queue);
        pthread_join(correlator_tid, NULL);
        return -1;
    }

    LOG_INFO("honeytrap started, press Ctrl+C to stop");
    while (!g_stop)
        sigsuspend(old_mask);
    LOG_INFO("shutting down");

    pthread_join(honeypot_tid, NULL);
    queue_close(app->queue);
    pthread_join(correlator_tid, NULL);
    return app->honeypot_failed ? -1 : 0;
}

int main(int argc, char **argv)
{
    const char *config_path = CONFIG_DEFAULT_PATH;
    bool report_only = false;
    int opt;
    while ((opt = getopt(argc, argv, "c:rh")) != -1) {
        switch (opt) {
        case 'c':
            config_path = optarg;
            break;
        case 'r':
            report_only = true;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }
    if (optind < argc) {
        LOG_ERROR("unexpected argument '%s'", argv[optind]);
        usage(argv[0]);
        return 1;
    }

    struct app *app = &g_app;
    config_set_defaults(&app->cfg);
    if (config_load(config_path, &app->cfg) != 0)
        return 1;

    if (report_only)
        return report_generate(app->cfg.storage_db_path, app->cfg.storage_report_path,
                               stdout) == 0 ? 0 : 1;

    sigset_t old_mask;
    if (setup_signals(&old_mask) != 0)
        return 1;

    int rc = run(app, &old_mask);

    correlator_destroy(app->correlator);
    db_close(app->db);
    app->correlator = NULL;
    app->db = NULL;

    if (rc == 0 || app->honeypot_failed) {
        if (report_generate(app->cfg.storage_db_path, app->cfg.storage_report_path,
                            stdout) != 0)
            rc = -1;
    }
    return rc == 0 ? 0 : 1;
}
