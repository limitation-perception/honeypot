#include "i2c.h"

#include <avr/io.h>

/* Чекаємо, поки апаратний I2C закінчить дію.
 * Лічильник потрібен, щоб плата не зависла, якщо дроти не підключені. */
static void i2c_wait(void)
{
    uint16_t n = 0;
    while (!(TWCR & (1 << TWINT)) && n < 50000)
        n++;
}

void i2c_init(void)
{
    TWSR = 0;                                   
    TWBR = (uint8_t)((F_CPU / 100000UL - 16) / 2);  
    TWCR = (1 << TWEN);                         /* увімкнути I2C */
}

int i2c_start(uint8_t addr)
{
    TWCR = (1 << TWINT) | (1 << TWSTA) | (1 << TWEN);   /* сигнал START */
    i2c_wait();

    TWDR = (uint8_t)(addr << 1);                         /* адреса + біт «пишемо» */
    TWCR = (1 << TWINT) | (1 << TWEN);
    i2c_wait();

    return (TWSR & 0xF8) == 0x18;   }

void i2c_write(uint8_t data)
{
    TWDR = data;
    TWCR = (1 << TWINT) | (1 << TWEN);
    i2c_wait();
}

void i2c_stop(void)
{
    TWCR = (1 << TWINT) | (1 << TWSTO) | (1 << TWEN);   /* сигнал STOP */
}
