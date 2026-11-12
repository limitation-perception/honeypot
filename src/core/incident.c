#include "core/incident.h"

static const char *const level_names[] = {
    [THREAT_LOW]    = "LOW",
    [THREAT_MEDIUM] = "MEDIUM",
    [THREAT_HIGH]   = "HIGH",
};

_Static_assert(sizeof level_names / sizeof level_names[0] == THREAT_LEVEL_COUNT,
               "level_names must have a name for every threat_level_t");

const char *threat_level_name(threat_level_t level)
{
    if ((unsigned)level >= THREAT_LEVEL_COUNT)
        return "UNKNOWN";
    return level_names[level];
}
