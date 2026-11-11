#include "core/correlator.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "core/log.h"

#define BRUTEFORCE_ATTEMPTS 3

struct tracked {
    struct incident inc;
    int             login_attempts;
    bool            scanned;
    bool            flooded;
    bool            arp_spoofed;
    bool            logged_in;
    bool            downloaded;
};

struct correlator {
    struct db      *db;
    FILE           *alerts;
    bool            color;
    time_t          timeout;
    struct tracked *items;
    size_t          count;
    size_t          cap;
};

static const char *const level_colors[] = {
    [THREAT_LOW]    = "\033[36m",
    [THREAT_MEDIUM] = "\033[33m",
    [THREAT_HIGH]   = "\033[1;31m",
};

_Static_assert(sizeof level_colors / sizeof level_colors[0] == THREAT_LEVEL_COUNT,
               "level_colors must have a color for every threat_level_t");

struct correlator *correlator_create(struct db *db, FILE *alerts, int incident_timeout_sec)
{
    struct correlator *c = calloc(1, sizeof *c);
    if (!c) {
        LOG_ERROR("cannot allocate correlator");
        return NULL;
    }
    c->db = db;
    c->alerts = alerts;
    c->color = isatty(fileno(alerts));
    c->timeout = incident_timeout_sec;
    return c;
}

void correlator_destroy(struct correlator *c)
{
    if (!c)
        return;
    free(c->items);
    free(c);
}

static struct tracked *find(const struct correlator *c, const char *src_ip)
{
    for (size_t i = 0; i < c->count; i++)
        if (strncmp(c->items[i].inc.src_ip, src_ip, EV_IP_LEN) == 0)
            return &c->items[i];
    return NULL;
}

static struct tracked *append(struct correlator *c)
{
    if (c->count == c->cap) {
        size_t cap = c->cap ? c->cap * 2 : 16;
        struct tracked *items = realloc(c->items, cap * sizeof *items);
        if (!items) {
            LOG_ERROR("cannot grow incident table to %zu entries", cap);
            return NULL;
        }
        c->items = items;
        c->cap = cap;
    }
    return &c->items[c->count++];
}

static void start_incident(struct tracked *t, const struct event *ev)
{
    memset(t, 0, sizeof *t);
    snprintf(t->inc.src_ip, sizeof t->inc.src_ip, "%.*s", EV_IP_LEN - 1, ev->src_ip);
    t->inc.first_seen = ev->timestamp;
    t->inc.last_seen = ev->timestamp;
    t->inc.level = THREAT_LOW;
}

static struct tracked *track(struct correlator *c, const struct event *ev, bool *is_new)
{
    struct tracked *t = find(c, ev->src_ip);
    if (t) {
        *is_new = ev->timestamp - t->inc.last_seen > c->timeout;
    } else {
        t = append(c);
        if (!t)
            return NULL;
        *is_new = true;
    }
    if (*is_new)
        start_incident(t, ev);
    return t;
}

static void apply(struct tracked *t, const struct event *ev)
{
    switch (ev->type) {
    case EV_PORT_SCAN:
        t->scanned = true;
        break;
    case EV_SYN_FLOOD:
        t->flooded = true;
        break;
    case EV_ARP_SPOOF:
        t->arp_spoofed = true;
        break;
    case EV_LOGIN_ATTEMPT:
        t->login_attempts++;
        break;
    case EV_LOGIN_SUCCESS:
        t->logged_in = true;
        break;
    case EV_DOWNLOAD_ATTEMPT:
        t->downloaded = true;
        break;
    case EV_CONNECT:
    case EV_COMMAND:
    case EV_DISCONNECT:
    case EV_TYPE_COUNT:
        break;
    }
    t->inc.event_count++;
    if (ev->timestamp > t->inc.last_seen)
        t->inc.last_seen = ev->timestamp;
}

static threat_level_t assess(const struct tracked *t)
{
    if (t->downloaded || (t->logged_in && t->scanned))
        return THREAT_HIGH;
    if (t->logged_in || t->flooded || t->arp_spoofed ||
        t->login_attempts >= BRUTEFORCE_ATTEMPTS)
        return THREAT_MEDIUM;
    return THREAT_LOW;
}

static void sanitize(char *dst, size_t dst_size, const char *src, size_t src_size)
{
    size_t n = 0;
    for (size_t i = 0; i < src_size && src[i] != '\0' && n + 1 < dst_size; i++) {
        unsigned char ch = (unsigned char)src[i];
        dst[n++] = (ch >= 0x20 && ch < 0x7f) ? (char)ch : '?';
    }
    dst[n] = '\0';
}

static void describe(char *out, size_t size, const struct event *ev)
{
    if (ev->type == EV_LOGIN_ATTEMPT || ev->type == EV_LOGIN_SUCCESS) {
        char user[EV_USER_LEN];
        char pass[EV_PASS_LEN];
        sanitize(user, sizeof user, ev->username, sizeof ev->username);
        sanitize(pass, sizeof pass, ev->password, sizeof ev->password);
        snprintf(out, size, "user='%s' pass='%s'", user, pass);
    } else {
        sanitize(out, size, ev->details, sizeof ev->details);
    }
}

static void alert(struct correlator *c, const struct tracked *t, bool is_new,
                  threat_level_t old_level, const struct event *ev)
{
    char when[16];
    struct tm tm;
    localtime_r(&ev->timestamp, &tm);
    strftime(when, sizeof when, "%H:%M:%S", &tm);

    char change[32];
    if (is_new)
        snprintf(change, sizeof change, "new");
    else
        snprintf(change, sizeof change, "%s -> %s", threat_level_name(old_level),
                 threat_level_name(t->inc.level));

    char ip[EV_IP_LEN];
    sanitize(ip, sizeof ip, t->inc.src_ip, sizeof t->inc.src_ip);

    char what[EV_USER_LEN + EV_PASS_LEN + 32];
    describe(what, sizeof what, ev);

    fprintf(c->alerts, "%s%s [ALERT] %-6s incident #%lld %s (%s): %s %s%s\n",
            c->color ? level_colors[t->inc.level] : "", when,
            threat_level_name(t->inc.level), (long long)t->inc.id, ip, change,
            event_type_name(ev->type), what, c->color ? "\033[0m" : "");
    fflush(c->alerts);
}

int correlator_process(struct correlator *c, const struct event *ev)
{
    bool is_new;
    struct tracked *t = track(c, ev, &is_new);
    if (!t)
        return -1;

    threat_level_t old_level = t->inc.level;
    apply(t, ev);
    t->inc.level = assess(t);

    int rc = 0;
    if (db_save_incident(c->db, &t->inc) != 0 || db_insert_event(c->db, ev, t->inc.id) != 0)
        rc = -1;

    if (is_new || t->inc.level > old_level)
        alert(c, t, is_new, old_level, ev);
    return rc;
}

void correlator_run(struct correlator *c, struct event_queue *q)
{
    struct event ev;
    while (queue_pop(q, &ev) == 0) {
        if (correlator_process(c, &ev) != 0)
            LOG_WARN("%s event from %.*s was not fully stored", event_type_name(ev.type),
                     EV_IP_LEN - 1, ev.src_ip);
    }
}

const struct incident *correlator_incident(const struct correlator *c, const char *src_ip)
{
    const struct tracked *t = find(c, src_ip);
    return t ? &t->inc : NULL;
}
