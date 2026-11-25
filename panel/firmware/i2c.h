#ifndef I2C_H
#define I2C_H

#include <stdint.h>

// увімкнути I2C (піни A4 = SDA, A5 = SCL) 
void i2c_init(void);

// почати передачу на пристрій
int i2c_start(uint8_t addr);

// надіслати 1 байт 
void i2c_write(uint8_t data);


void i2c_stop(void);

#endif
