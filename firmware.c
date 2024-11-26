#include <stdio.h>
#include <stdbool.h>
#include <stdatomic.h>
#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "hardware/spi.h"

#define SPI_SCK_PIN		18
#define SPI_TX_PIN		19
#define SPI_RX_PIN		16
#define SPI_CSN_PIN		17

#define FLASH_CMD_READ				0x03
#define FLASH_CMD_ERASE_4K_SECTOR	0x20
#define FLASH_CMD_ERASE_32K_BLOCK	0x52
#define FLASH_CMD_ERASE_64K_BLOCK	0xD8
#define FLASH_CMD_AAI_PROGRAM		0xAD
#define FLASH_CMD_WRITE_EN			0x06
#define FLASH_CMD_READ_STATUS		0x05

#define FLASH_STATUS_BUSY_MASK 0x01

#define BUFFER_SECTION_SIZE (64 * 1024)
#define BUFFER_SECTIONS 4
#define BUFFER_SIZE (BUFFER_SECTION_SIZE * BUFFER_SECTIONS)

static volatile uint8_t __aligned(4) __uninitialized_ram(buffer)[BUFFER_SIZE];
static _Atomic uint32_t __aligned(4) section_locks = 0;
static _Atomic uint32_t __aligned(4) section_sizes[BUFFER_SECTIONS];

void lock_section(int sect) {
	uint32_t mask = 1U << sect;
	atomic_fetch_or(&section_locks, mask);
}

void unlock_section(int sect) {
	uint32_t mask = ~(1U << sect);
	atomic_fetch_and(&section_locks, mask);
}

bool is_section_locked(int sect) {
	uint32_t locks = atomic_load(&section_locks);
	uint32_t mask = 1U << sect;
	return (locks & mask) != 0;
}

void set_section_size(int sect, int nbytes) {
	atomic_store(&section_sizes[sect], (uint32_t) nbytes);
}

int get_section_size(int sect) {
	return (int) atomic_load(&section_sizes[sect]);
}

static inline void cs_select(uint cs_pin) {
	asm volatile("nop \n nop \n nop");
	gpio_put(cs_pin, 0);
	asm volatile("nop \n nop \n nop");
}

static inline void cs_deselect(uint cs_pin) {
	asm volatile("nop \n nop \n nop");
	gpio_put(cs_pin, 1);
	asm volatile("nop \n nop \n nop");
}

void __not_in_flash_func(flash_read)(spi_inst_t *spi, uint cs_pin, uint32_t addr, uint8_t *buf, size_t len) {
	uint8_t cmdbuf[4] = {
		FLASH_CMD_READ,
		addr >> 16,
		addr >> 8,
		addr
	};
	cs_select(cs_pin);
	spi_write_blocking(spi, cmdbuf, 4);
	spi_read_blocking(spi, 0, buf, len);
	cs_deselect(cs_pin);
}

void __not_in_flash_func(flash_write_enable)(spi_inst_t *spi, uint cs_pin) {
	cs_select(cs_pin);
	uint8_t cmd = FLASH_CMD_WRITE_EN;
	spi_write_blocking(spi, &cmd, 1);
	cs_deselect(cs_pin);
}

void __not_in_flash_func(flash_wait_done)(spi_inst_t *spi, uint cs_pin) {
	uint8_t status;
	do {
		cs_select(cs_pin);
		uint8_t buf[2] = {FLASH_CMD_READ_STATUS, 0};
		spi_write_read_blocking(spi, buf, buf, 2);
		cs_deselect(cs_pin);
		status = buf[1];
	} while (status & FLASH_STATUS_BUSY_MASK);
}

void __not_in_flash_func(flash_erase)(spi_inst_t *spi, uint cs_pin, uint8_t erase_cmd, uint32_t addr) {
	uint8_t cmdbuf[4] = {
		cmd,
		addr >> 16,
		addr >> 8,
		addr
	};
	flash_write_enable(spi, cs_pin);
	cs_select(cs_pin);
	spi_write_blocking(spi, cmdbuf, 4);
	cs_deselect(cs_pin);
	flash_wait_done(spi, cs_pin);
}

void core1_entry() {
	spi_init(spi0, 1000 * 1000);
	spi_set_format(spi0, 8, SPI_CPOL_1, SPI_CPHA_1, SPI_MSB_FIRST);
	gpio_set_function(SPI_SCK_PIN, GPIO_FUNC_SPI);
	gpio_set_function(SPI_TX_PIN, GPIO_FUNC_SPI);
	gpio_set_function(SPI_RX_PIN, GPIO_FUNC_SPI);

	gpio_init(SPI_CSN_PIN);
	gpio_put(SPI_CSN_PIN, 1);
	gpio_set_dir(SPI_CSN_PIN, GPIO_OUT);

	while (true) {
		sleep_ms(1000);
	}
}

int main() {
	for (int i = 0; i < BUFFER_SECTIONS; ++i) {
		atomic_store(&section_sizes[i], 0);
	}

	stdio_init_all();
	multicore_launch_core1(core1_entry);

	while (true) {
		sleep_ms(1000);
	}
}
