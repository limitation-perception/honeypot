#include "oled.h"

#include <avr/pgmspace.h>

#include "font.h"
#include "i2c.h"

#define OLED_ADDR 0x3C

static int oled_ok = 0;

static void cmd(uint8_t c)
{
    i2c_start(OLED_ADDR);
    i2c_write(0x00);
    i2c_write(c);
    i2c_stop();
}

static void set_pos(uint8_t row, uint8_t x)
{
    cmd(0xB0 + row);
    cmd(0x00 + (x & 0x0F));
    cmd(0x10 + (x >> 4));
}

static const uint8_t *glyph(char c)
{
    if (c < 32 || c > 126)
        c = '?';
    return font5x7[c - 32];
}

int oled_init(void)
{
    i2c_init();

    oled_ok = i2c_start(OLED_ADDR);
    i2c_stop();
    if (!oled_ok)
        return 0;

    static const uint8_t init_cmds[] = {
        0xAE,
        0xD5, 0x80,
        0xA8, 0x3F,
        0xD3, 0x00,
        0x40,
        0x8D, 0x14,
        0x20, 0x02,
        0xA1,
        0xC8,
        0xDA, 0x12,
        0x81, 0xCF,
        0xD9, 0xF1,
        0xDB, 0x40,
        0xA4,
        0xA6,
        0xAF
    };
    for (uint8_t i = 0; i < sizeof init_cmds; i++)
        cmd(init_cmds[i]);

    oled_clear();
    return 1;
}

void oled_clear_row(uint8_t row)
{
    if (!oled_ok)
        return;
    set_pos(row, 0);
    i2c_start(OLED_ADDR);
    i2c_write(0x40);
    for (uint8_t x = 0; x < 128; x++)
        i2c_write(0x00);
    i2c_stop();
}

void oled_clear(void)
{
    for (uint8_t row = 0; row < 8; row++)
        oled_clear_row(row);
}

void oled_print(uint8_t row, uint8_t col, const char *text)
{
    if (!oled_ok)
        return;
    set_pos(row, (uint8_t)(col * 6));
    i2c_start(OLED_ADDR);
    i2c_write(0x40);
    while (*text != '\0' && col < 21) {
        const uint8_t *g = glyph(*text);
        for (uint8_t i = 0; i < 5; i++)
            i2c_write(pgm_read_byte(&g[i]));
        i2c_write(0x00);
        text++;
        col++;
    }
    i2c_stop();
}

static uint8_t stretch(uint8_t bits4)
{
    uint8_t out = 0;
    for (uint8_t i = 0; i < 4; i++)
        if (bits4 & (1 << i))
            out |= (uint8_t)(3 << (i * 2));
    return out;
}

void oled_print_big(uint8_t row, uint8_t col, const char *text)
{
    if (!oled_ok)
        return;

    for (uint8_t half = 0; half < 2; half++) {
        const char *t = text;
        uint8_t c = col;
        set_pos((uint8_t)(row + half), (uint8_t)(col * 12));
        i2c_start(OLED_ADDR);
        i2c_write(0x40);
        while (*t != '\0' && c < 10) {
            const uint8_t *g = glyph(*t);
            for (uint8_t i = 0; i < 5; i++) {
                uint8_t bits = pgm_read_byte(&g[i]);
                uint8_t part = half == 0 ? (bits & 0x0F) : (bits >> 4);
                uint8_t b = stretch(part);
                i2c_write(b);
                i2c_write(b);
            }
            i2c_write(0x00);
            i2c_write(0x00);
            t++;
            c++;
        }
        i2c_stop();
    }
}