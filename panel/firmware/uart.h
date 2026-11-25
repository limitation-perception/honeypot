#ifndef UART_H
#define UART_H

#define UART_LINE_LEN 64

void uart_init(void);
int uart_get_line(char *buf, int size);

#endif