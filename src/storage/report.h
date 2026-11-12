#ifndef STORAGE_REPORT_H
#define STORAGE_REPORT_H

#include <stdio.h>

int report_generate(const char *db_path, const char *html_path, FILE *summary);

#endif
