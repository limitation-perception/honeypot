#ifndef TESTS_DB_CHECK_H
#define TESTS_DB_CHECK_H

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "unity.h"

#define TEMP_DB_PATH_LEN 32

static inline void make_temp_db_path(char path[TEMP_DB_PATH_LEN])
{
    snprintf(path, TEMP_DB_PATH_LEN, "%s", "/tmp/honeytrap_test_XXXXXX");
    int fd = mkstemp(path);
    TEST_ASSERT_TRUE(fd >= 0);
    close(fd);
}

static inline long long query_int(sqlite3 *conn, const char *sql)
{
    sqlite3_stmt *st;
    TEST_ASSERT_EQUAL_INT_MESSAGE(SQLITE_OK, sqlite3_prepare_v2(conn, sql, -1, &st, NULL), sql);
    TEST_ASSERT_EQUAL_INT_MESSAGE(SQLITE_ROW, sqlite3_step(st), sql);
    long long v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

static inline void query_text(sqlite3 *conn, const char *sql, char *out, size_t size)
{
    sqlite3_stmt *st;
    TEST_ASSERT_EQUAL_INT_MESSAGE(SQLITE_OK, sqlite3_prepare_v2(conn, sql, -1, &st, NULL), sql);
    TEST_ASSERT_EQUAL_INT_MESSAGE(SQLITE_ROW, sqlite3_step(st), sql);
    const unsigned char *s = sqlite3_column_text(st, 0);
    snprintf(out, size, "%s", s ? (const char *)s : "(null)");
    sqlite3_finalize(st);
}

#endif
