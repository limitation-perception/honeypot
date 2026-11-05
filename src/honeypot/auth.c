#include "auth.h"

#include "core/event.h"

int auth_try(struct auth_state *st, const struct hp_session *s,
             const char *user, const char *pass)
{
    st->tries++;

    /* кожну пару логін/пароль записуємо як подію */
    struct event ev = hp_event(s, EV_LOGIN_ATTEMPT);
    event_set_str(ev.username, sizeof ev.username, user);
    event_set_str(ev.password, sizeof ev.password, pass);
    hp_emit(s, &ev);

    if (st->tries >= s->login_after) {
        st->authenticated = 1;

        struct event ok = hp_event(s, EV_LOGIN_SUCCESS);
        event_set_str(ok.username, sizeof ok.username, user);
        hp_emit(s, &ok);
        return 1;  
    }
    return 0;     
}