#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/log.h"

enum opt_type { OPT_INT, OPT_STR };

struct option_def {
    const char   *key;
    enum opt_type type;
    size_t        offset;
    long          min, max;
};

#define INT_OPT(k, field, lo, hi) { k, OPT_INT, offsetof(struct config, field), lo, hi }
#define STR_OPT(k, field)         { k, OPT_STR, offsetof(struct config, field), 0, 0 }

static const struct option_def options[] = {
    INT_OPT("honeypot.port",           honeypot_port,           1, 65535),
    INT_OPT("honeypot.login_after",    honeypot_login_after,    1, 100),
    INT_OPT("honeypot.max_clients",    honeypot_max_clients,    1, 10000),
    STR_OPT("ids.interface",           ids_interface),
    STR_OPT("ids.pcap_file",           ids_pcap_file),
    INT_OPT("ids.portscan_ports",      ids_portscan_ports,      1, 65535),
    INT_OPT("ids.portscan_window_sec", ids_portscan_window_sec, 1, 3600),
    INT_OPT("ids.synflood_syns",       ids_synflood_syns,       1, INT_MAX),
    INT_OPT("ids.synflood_window_sec", ids_synflood_window_sec, 1, 3600),
    INT_OPT("core.queue_capacity",     core_queue_capacity,     1, 1000000),
    STR_OPT("storage.db_path",         storage_db_path),
    STR_OPT("storage.report_path",     storage_report_path),
};

void config_set_defaults(struct config *cfg)
{
    memset(cfg, 0, sizeof *cfg);
    cfg->honeypot_port = 2222;
    cfg->honeypot_login_after = 3;
    cfg->honeypot_max_clients = 32;
    snprintf(cfg->ids_interface, sizeof cfg->ids_interface, "%s", "eth0");
    cfg->ids_portscan_ports = 20;
    cfg->ids_portscan_window_sec = 3;
    cfg->ids_synflood_syns = 100;
    cfg->ids_synflood_window_sec = 1;
    cfg->core_queue_capacity = 1024;
    snprintf(cfg->storage_db_path, sizeof cfg->storage_db_path, "%s", "honeytrap.db");
    snprintf(cfg->storage_report_path, sizeof cfg->storage_report_path, "%s", "report.html");
}

static char *trim(char *s)
{
    while (isspace((unsigned char)*s))
        s++;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1]))
        end--;
    *end = '\0';
    return s;
}

static const struct option_def *find_option(const char *key)
{
    for (size_t i = 0; i < sizeof options / sizeof options[0]; i++)
        if (strcmp(options[i].key, key) == 0)
            return &options[i];
    return NULL;
}

static int set_option(const struct option_def *opt, const char *value,
                      struct config *cfg, const char *path, int lineno)
{
    char *field = (char *)cfg + opt->offset;

    if (opt->type == OPT_STR) {
        if (strlen(value) >= CFG_STR_LEN) {
            LOG_ERROR("%s:%d: value of '%s' is too long (max %d chars)",
                      path, lineno, opt->key, CFG_STR_LEN - 1);
            return -1;
        }
        snprintf(field, CFG_STR_LEN, "%s", value);
        return 0;
    }

    char *end;
    errno = 0;
    long n = strtol(value, &end, 10);
    if (*value == '\0' || *end != '\0' || errno == ERANGE) {
        LOG_ERROR("%s:%d: '%s' expects an integer, got '%s'",
                  path, lineno, opt->key, value);
        return -1;
    }
    if (n < opt->min || n > opt->max) {
        LOG_ERROR("%s:%d: '%s' = %ld is out of range [%ld, %ld]",
                  path, lineno, opt->key, n, opt->min, opt->max);
        return -1;
    }
    *(int *)field = (int)n;
    return 0;
}

int config_load(const char *path, struct config *cfg)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        LOG_ERROR("cannot open config '%s': %s", path, strerror(errno));
        return -1;
    }

    char line[1024];
    int lineno = 0;
    int rc = 0;

    while (fgets(line, sizeof line, f)) {
        lineno++;

        if (!strchr(line, '\n') && !feof(f)) {
            LOG_ERROR("%s:%d: line is too long (max %zu chars)",
                      path, lineno, sizeof line - 2);
            rc = -1;
            break;
        }

        char *hash = strchr(line, '#');
        if (hash)
            *hash = '\0';
        char *s = trim(line);
        if (*s == '\0')
            continue;

        char *eq = strchr(s, '=');
        if (!eq) {
            LOG_ERROR("%s:%d: expected 'key = value', got '%s'", path, lineno, s);
            rc = -1;
            break;
        }
        *eq = '\0';
        char *key = trim(s);
        char *value = trim(eq + 1);

        const struct option_def *opt = find_option(key);
        if (!opt) {
            LOG_ERROR("%s:%d: unknown key '%s'", path, lineno, key);
            rc = -1;
            break;
        }
        if (set_option(opt, value, cfg, path, lineno) != 0) {
            rc = -1;
            break;
        }
    }

    if (rc == 0 && ferror(f)) {
        LOG_ERROR("error reading config '%s': %s", path, strerror(errno));
        rc = -1;
    }
    fclose(f);
    return rc;
}
