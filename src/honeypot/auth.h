#ifndef HONEYPOT_AUTH_H
#define HONEYPOT_AUTH_H

#include "session.h"

/* cтан входу для ОДНІЄЇ сесії. */
struct auth_state {
    int tries;          
    int authenticated;  
};

/* oбробити одну спробу входу. */
int auth_try(struct auth_state *st, const struct hp_session *s,
             const char *user, const char *pass);

#endif