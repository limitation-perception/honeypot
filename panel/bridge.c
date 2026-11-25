#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static int serial_open(const char *path)
{
    int fd = open(path, O_RDWR | O_NOCTTY);
    if (fd < 0)
        return -1;

    struct termios tio;
    if (tcgetattr(fd, &tio) != 0) {
        close(fd);
        return -1;
    }
    cfmakeraw(&tio);
    cfsetispeed(&tio, B9600);
    cfsetospeed(&tio, B9600);
    tio.c_cflag |= CLOCAL | CREAD;
    if (tcsetattr(fd, TCSANOW, &tio) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int alert_to_panel(const char *line, char *out, size_t size)
{
    const char *p = strstr(line, "[ALERT] ");
    if (p == NULL)
        return 0;
    p += strlen("[ALERT] ");

    char level = p[0];
    if (level != 'L' && level != 'M' && level != 'H')
        return 0;

    char ip[64];
    if (sscanf(p, "%*s incident #%*d %63s", ip) != 1)
        return 0;

    const char *msg = strstr(p, "): ");
    msg = msg ? msg + 3 : "";

    snprintf(out, size, "%c;%s;%s", level, ip, msg);

    size_t n = strlen(out);
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r' || out[n - 1] == ' '))
        out[--n] = '\0';
    return 1;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s /dev/ttyUSB0\n", argv[0]);
        return 1;
    }

    int fd = serial_open(argv[1]);
    if (fd < 0) {
        perror(argv[1]);
        return 1;
    }

    fprintf(stderr, "bridge: waiting for the panel...\n");
    sleep(4);
    fprintf(stderr, "bridge: ready, forwarding alerts to %s\n", argv[1]);

    char line[1024];
    char out[128];
    while (fgets(line, sizeof line, stdin) != NULL) {
        fputs(line, stdout);
        fflush(stdout);

        if (alert_to_panel(line, out, sizeof out - 1)) {
            size_t n = strlen(out);
            out[n] = '\n';
            if (write(fd, out, n + 1) < 0)
                perror("bridge: write");
        }
    }

    close(fd);
    return 0;
}
