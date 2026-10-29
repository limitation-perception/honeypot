#ifndef CORE_LOG_H
#define CORE_LOG_H

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#define LOG_INFO(...)  log_write("INFO",  __FILE__, __LINE__, __VA_ARGS__)
#define LOG_WARN(...)  log_write("WARN",  __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ERROR(...) log_write("ERROR", __FILE__, __LINE__, __VA_ARGS__)

static inline void log_write(const char *level, const char *file, int line,
                             const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

static inline void log_write(const char *level, const char *file, int line,
                             const char *fmt, ...)
{
    char ts[20];
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tm);

    va_list ap;
    flockfile(stderr);
    fprintf(stderr, "%s [%s] %s:%d: ", ts, level, file, line);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    funlockfile(stderr);
}

#endif
