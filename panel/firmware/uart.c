#include "uart.h"

#include <avr/interrupt.h>
#include <avr/io.h>

#define BAUD 9600
#define UBRR_VALUE (F_CPU / 16 / BAUD - 1)

static char rx_buf[UART_LINE_LEN];
static uint8_t rx_len = 0;

static char ready_buf[UART_LINE_LEN];
static volatile uint8_t ready = 0;

void uart_init(void)
{
    UBRR0H = (uint8_t)(UBRR_VALUE >> 8);
    UBRR0L = (uint8_t)UBRR_VALUE;
    UCSR0B = (1 << RXEN0) | (1 << RXCIE0);
    UCSR0C = (1 << UCSZ01) | (1 << UCSZ00);
}

ISR(USART_RX_vect)
{
    char c = UDR0;

    if (c == '\r')
        return;

    if (c == '\n') {
        if (!ready) {
            for (uint8_t i = 0; i < rx_len; i++)
                ready_buf[i] = rx_buf[i];
            ready_buf[rx_len] = '\0';
            ready = 1;
        }
        rx_len = 0;
        return;
    }

    if (rx_len < UART_LINE_LEN - 1)
        rx_buf[rx_len++] = c;
}

int uart_get_line(char *buf, int size)
{
    if (!ready)
        return 0;

    cli();
    int i = 0;
    while (ready_buf[i] != '\0' && i < size - 1) {
        buf[i] = ready_buf[i];
        i++;
    }
    buf[i] = '\0';
    ready = 0;
    sei();
    return 1;
}