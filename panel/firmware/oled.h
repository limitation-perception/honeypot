#ifndef OLED_H
#define OLED_H

#include <stdint.h>

int oled_init(void);
void oled_clear(void);
void oled_clear_row(uint8_t row);
void oled_print(uint8_t row, uint8_t col, const char *text);
void oled_print_big(uint8_t row, uint8_t col, const char *text);

#endif