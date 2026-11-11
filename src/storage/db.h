#ifndef STORAGE_DB_H
#define STORAGE_DB_H

#include <stdint.h>

#include "core/event.h"
#include "core/incident.h"

struct db;

struct db *db_open(const char *path);
void db_close(struct db *db);

int db_save_incident(struct db *db, struct incident *inc);
int db_insert_event(struct db *db, const struct event *ev, int64_t incident_id);

#endif
