#ifndef CORE_INCIDENT_H
#define CORE_INCIDENT_H

#include <stdint.h>
#include <time.h>

#include "core/event.h"

typedef enum {
    THREAT_LOW,
    THREAT_MEDIUM,
    THREAT_HIGH,
    THREAT_LEVEL_COUNT
} threat_level_t;

struct incident {
    int64_t        id;
    char           src_ip[EV_IP_LEN];
    time_t         first_seen;
    time_t         last_seen;
    threat_level_t level;
    int            event_count;
};

const char *threat_level_name(threat_level_t level);

#endif
