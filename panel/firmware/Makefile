# Прошивка панелі тривоги HoneyTrap для Arduino Uno (ATmega328P)
#
#   make                         зібрати panel.hex
#   make flash                   залити на плату (порт за замовчуванням /dev/ttyACM0)
#   make flash PORT=/dev/ttyUSB0 якщо плата на чипі CH340
#   make clean

MCU   := atmega328p
F_CPU := 16000000UL
PORT  ?= /dev/ttyACM0

CC      := avr-gcc
CFLAGS  := -std=c11 -mmcu=$(MCU) -DF_CPU=$(F_CPU) -Os -Wall -Wextra
SRCS    := main.c uart.c i2c.c oled.c

all: panel.hex

panel.elf: $(SRCS) uart.h i2c.h oled.h font.h
	$(CC) $(CFLAGS) -o $@ $(SRCS)
	avr-size --mcu=$(MCU) -C $@

panel.hex: panel.elf
	avr-objcopy -O ihex -R .eeprom $< $@

flash: panel.hex
	avrdude -c arduino -p m328p -P $(PORT) -b 115200 -U flash:w:panel.hex:i

clean:
	rm -f panel.elf panel.hex

.PHONY: all flash clean
