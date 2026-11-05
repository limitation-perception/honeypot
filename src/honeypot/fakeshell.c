#include "fakeshell.h"

#include <string.h>

#include "core/event.h"
#include "net.h"

static void emit(const struct hp_session *s, event_type_t type, const char *detail)
{
    struct event ev = hp_event(s, type);
    event_set_str(ev.details, sizeof ev.details, detail);
    hp_emit(s, &ev);
}

void shell_exec(const struct hp_session *s, const char *cmd)
{
    if (cmd[0] == '\0')
        return;                       /* порожній рядок — нічого */

    emit(s, EV_COMMAND, cmd);         /* кожну команду — в подію */

    /* заготовлені відповіді, нічого не виконується по-справжньому */
    if (strcmp(cmd, "whoami") == 0)
        net_send(s->conn, "root\r\n");
    else if (strcmp(cmd, "pwd") == 0)
        net_send(s->conn, "/root\r\n");
    else if (strcmp(cmd, "id") == 0)
        net_send(s->conn, "uid=0(root) gid=0(root) groups=0(root)\r\n");
    else if (strcmp(cmd, "uname -a") == 0)
        net_send(s->conn, "Linux srv 5.15.0-generic #1 SMP x86_64 GNU/Linux\r\n");
    else if (strcmp(cmd, "ls") == 0)
        net_send(s->conn, "backup.tar.gz  notes.txt\r\n");
    else if (strncmp(cmd, "wget", 4) == 0 || strncmp(cmd, "curl", 4) == 0) {
        emit(s, EV_DOWNLOAD_ATTEMPT, cmd);  /* зберігаємо URL/команду */
        net_send(s->conn, "Resolving host... connected.\r\n");  /* БЕЗ завантаження */
    }
    else if (strncmp(cmd, "sudo ", 5) == 0)
        shell_exec(s, cmd + 5);       /* ти вже root — обробляємо решту команди */
    else if (strncmp(cmd, "apt", 3) == 0)
        net_send(s->conn, "Reading package lists... Done\r\n");
    else if (strcmp(cmd, "cat /etc/passwd") == 0)
        net_send(s->conn, "root:x:0:0:root:/root:/bin/bash\r\n");
    else if (strcmp(cmd, "cd") == 0 || strncmp(cmd, "cd ", 3) == 0)
        ;                             /* cd нічого не виводить, як у справжньому shell */
    else
        net_send(s->conn, "bash: command not found\r\n");
}