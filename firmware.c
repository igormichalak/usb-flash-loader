#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include <stdatomic.h>

#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "hardware/gpio.h"
#include "hardware/spi.h"
#include "bsp/board_api.h"
#include "tusb.h"

#define SPI_SCK_PIN	18
#define SPI_TX_PIN	19
#define SPI_RX_PIN	16
#define SPI_CSN_PIN	17

#define FLASH_CMD_READ				0x03
#define FLASH_CMD_ERASE_4K_SECTOR	0x20
#define FLASH_CMD_ERASE_32K_BLOCK	0x52
#define FLASH_CMD_ERASE_64K_BLOCK	0xD8
#define FLASH_CMD_BYTE_PROGRAM		0x02
#define FLASH_CMD_AAI_PROGRAM		0xAD
#define FLASH_CMD_WR_ENABLE			0x06
#define FLASH_CMD_WR_DISABLE		0x04
#define FLASH_CMD_HW_BUSY_ENABLE	0x70
#define FLASH_CMD_HW_BUSY_DISABLE	0x80
#define FLASH_CMD_STATUS_READ		0x05
#define FLASH_CMD_STATUS_WR			0x01
#define FLASH_CMD_STATUS_WR_ENABLE	0x50

#define FLASH_STATUS_BUSY_MASK 0x01

#define BUFFER_SECTION_SIZE (64 * 1024)
#define BUFFER_SECTIONS 4
#define BUFFER_SIZE (BUFFER_SECTION_SIZE * BUFFER_SECTIONS)

static void cdc_task(void);

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

void __not_in_flash_func(flash_write_enable)(spi_inst_t *spi) {
	uint8_t cmd = FLASH_CMD_WR_ENABLE;
	spi_write_blocking(spi, &cmd, 1);
}

void __not_in_flash_func(flash_write_disable)(spi_inst_t *spi) {
	uint8_t cmd = FLASH_CMD_WR_DISABLE;
	spi_write_blocking(spi, &cmd, 1);
}

void __not_in_flash_func(flash_wait_done)(spi_inst_t *spi) {
	uint8_t status;
	do {
		uint8_t buf[2] = {FLASH_CMD_STATUS_READ, 0};
		spi_write_read_blocking(spi, buf, buf, 2);
		status = buf[1];
	} while (status & FLASH_STATUS_BUSY_MASK);
}

void __not_in_flash_func(flash_hw_wait_done)(spi_inst_t *spi, uint cs_pin, uint rx_pin) {
	gpio_set_function(cs_pin, GPIO_FUNC_SIO);
	while (!gpio_get_pad(rx_pin));
	gpio_set_function(cs_pin, GPIO_FUNC_SPI);
}

void __not_in_flash_func(flash_unlock)(spi_inst_t *spi) {
	uint8_t enable_cmd = FLASH_CMD_STATUS_WR_ENABLE;
	spi_write_blocking(spi, &enable_cmd, 1);
	uint8_t cmdbuf[2] = {FLASH_CMD_STATUS_WR, 0x00};
	spi_write_blocking(spi, cmdbuf, 2);
}

void __not_in_flash_func(flash_read)(spi_inst_t *spi, uint cs_pin, uint32_t addr, uint8_t *buf, size_t len) {
	uint8_t cmdbuf[4] = {
		FLASH_CMD_READ,
		addr >> 16,
		addr >> 8,
		addr,
	};

	const size_t fifo_depth = 8;
	const uint8_t repeated_tx_data = 0;
	size_t tx_cmd_remaining = 4;
	size_t tx_data_remaining = len;
	size_t rx_cmd_remaining = 4;
	size_t rx_data_remaining = len;

	gpio_set_function(cs_pin, GPIO_FUNC_SIO);
	asm volatile("nop \n nop \n nop");

	while (tx_cmd_remaining || tx_data_remaining || rx_cmd_remaining || rx_data_remaining) {
		size_t tx_remaining = tx_cmd_remaining + tx_data_remaining;
		size_t rx_remaining = rx_cmd_remaining + rx_data_remaining;
		if (spi_is_writable(spi) && rx_remaining < tx_remaining + fifo_depth) {
			if (tx_cmd_remaining) {
				spi_get_hw(spi)->dr = (uint32_t) cmdbuf[4 - tx_cmd_remaining];
				--tx_cmd_remaining;
			} else if (tx_data_remaining) {
				spi_get_hw(spi)->dr = (uint32_t) repeated_tx_data;
				--tx_data_remaining;
			}
		}
		if (spi_is_readable(spi)) {
			if (rx_cmd_remaining) {
				(void) spi_get_hw(spi)->dr;
				--rx_cmd_remaining;
			} else if (rx_data_remaining) {
				*buf++ = (uint8_t) spi_get_hw(spi)->dr;
				--rx_data_remaining;
			}
		}
	}

	while (spi_get_hw(spi)->sr & SPI_SSPSR_BSY_BITS);
	asm volatile("nop \n nop \n nop");
	gpio_set_function(cs_pin, GPIO_FUNC_SPI);
}

void __not_in_flash_func(flash_erase)(spi_inst_t *spi, uint8_t erase_cmd, uint32_t addr) {
	uint8_t cmdbuf[4] = {
		erase_cmd,
		addr >> 16,
		addr >> 8,
		addr,
	};
	flash_write_enable(spi);
	spi_write_blocking(spi, cmdbuf, sizeof(cmdbuf));
	flash_wait_done(spi);
}

void __not_in_flash_func(flash_byte_write)(spi_inst_t *spi, uint32_t addr, uint8_t data) {
	uint8_t cmdbuf[5] = {
		FLASH_CMD_BYTE_PROGRAM,
		addr >> 16,
		addr >> 8,
		addr,
		data,
	};
	flash_write_enable(spi);
	spi_write_blocking(spi, cmdbuf, sizeof(cmdbuf));
	flash_wait_done(spi);
}

void __not_in_flash_func(flash_aai_write)(spi_inst_t *spi, uint cs_pin, uint rx_pin, uint32_t addr, uint8_t *src, size_t len) {
	uint8_t ebsy_cmd = FLASH_CMD_HW_BUSY_ENABLE;
	spi_write_blocking(spi, &ebsy_cmd, 1);

	flash_write_enable(spi);

	uint8_t byte_0 = len < 1 ? 0 : *src++;
	uint8_t byte_1 = len < 2 ? 0 : *src++;
	uint8_t cmdbuf[6] = {
		FLASH_CMD_AAI_PROGRAM,
		addr >> 16,
		addr >> 8,
		addr,
		byte_0,
		byte_1,
	};
	spi_write_blocking(spi, cmdbuf, sizeof(cmdbuf));

	for (size_t sent = 2; sent < len; sent += 2) {
		flash_hw_wait_done(spi, cs_pin, rx_pin);

		byte_0 = *src++;
		byte_1 = (sent == len-1) ? 0 : *src++;
		uint8_t aai_cmdbuf[3] = {
			FLASH_CMD_AAI_PROGRAM,
			byte_0,
			byte_1,
		};
		spi_write_blocking(spi, aai_cmdbuf, sizeof(aai_cmdbuf));
	}

	flash_hw_wait_done(spi, cs_pin, rx_pin);
	flash_write_disable(spi);

	uint8_t dbsy_cmd = FLASH_CMD_HW_BUSY_DISABLE;
	spi_write_blocking(spi, &dbsy_cmd, 1);

	flash_wait_done(spi);
}

void core1_entry() {
	gpio_set_dir(SPI_CSN_PIN, GPIO_OUT);
	gpio_put(SPI_CSN_PIN, 0);

	spi_init(spi0, 1000 * 1000);
	spi_set_format(spi0, 8, SPI_CPOL_1, SPI_CPHA_1, SPI_MSB_FIRST);
	gpio_set_function(SPI_SCK_PIN, GPIO_FUNC_SPI);
	gpio_set_function(SPI_TX_PIN, GPIO_FUNC_SPI);
	gpio_set_function(SPI_RX_PIN, GPIO_FUNC_SPI);
	gpio_set_function(SPI_CSN_PIN, GPIO_FUNC_SPI);

	flash_unlock(spi0);

	while (true) {}
}

int main(void) {
	for (int i = 0; i < BUFFER_SECTIONS; ++i) {
		atomic_store(&section_sizes[i], 0);
	}
	multicore_launch_core1(core1_entry);

	board_init();
	tusb_rhport_init_t device_init = {
		.role = TUSB_ROLE_DEVICE,
		.speed = TUSB_SPEED_AUTO,
	};
	tusb_init(BOARD_TUD_RHPORT, &device_init);

	if (board_init_after_tusb) {
		board_init_after_tusb();
	}

	while (true) {
		tud_task();
		cdc_task();
	}
}

void tud_mount_cb(void) {}
void tud_unmount_cb(void) {}

static void cdc_task(void) {
	if (!tud_cdc_n_available(0)) {
		return;
	}
}

