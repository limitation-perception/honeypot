#ifndef HONEYPOT_FAKE_SHELL_H
#define HONEYPOT_FAKE_SHELL_H

#include "session.h"

void shell_exec(const struct hp_session *s, const char *cmd);

#endif