#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "core/log.h"

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void usage(const char *prog)
{
    fprintf(stderr, "usage: %s [-c config_file]\n"
                    "  -c  config file (default: %s)\n",
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

int main(int argc, char **argv)
{
    const char *config_path = CONFIG_DEFAULT_PATH;
    int opt;
    while ((opt = getopt(argc, argv, "c:h")) != -1) {
        switch (opt) {
        case 'c':
            config_path = optarg;
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

    struct config cfg;
    config_set_defaults(&cfg);
    if (config_load(config_path, &cfg) != 0)
        return 1;

    sigset_t old_mask;
    if (setup_signals(&old_mask) != 0)
        return 1;

    LOG_INFO("honeytrap started (config: %s, honeypot port: %d)",
             config_path, cfg.honeypot_port);

    while (!g_stop)
        sigsuspend(&old_mask);

    LOG_INFO("shutting down");

    return 0;
}
