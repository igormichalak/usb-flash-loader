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

#define DEBUG false

#define CMD_ERASE_RANGES	0x87
#define CMD_DATA_SLICE		0x66
#define CMD_END_OF_DATA		0xBA

#define RESP_SUCCESS			0x72
#define RESP_ERR_VERIFICATION	0xC4

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

#define FLASH_ERASE_SECTOR_SIZE 4096

#define BUFFER_SECTION_SIZE (64 * 1024)
#define BUFFER_SECTIONS 4
#define BUFFER_SIZE (BUFFER_SECTION_SIZE * BUFFER_SECTIONS)

typedef struct {
	uint32_t address;
	int sectors;		// Number of 4K sectors
} erase_range_t;

static volatile uint8_t __aligned(4) __uninitialized_ram(glob_buffer)[BUFFER_SIZE];
static _Atomic uint32_t __aligned(4) section_locks = 0;
static _Atomic uint32_t __aligned(4) section_sizes[BUFFER_SECTIONS];

static int write_section = 0;
static int write_sect_pos = 0;
static uint8_t *write_ptr = NULL;

static int read_section = 0;
static int read_sect_pos = 0;
static uint8_t *read_ptr = NULL;

static absolute_time_t last_reception_time;
static bool rx_in_progress = false;

void auto_lock_task(void);

uint32_t read_locks(void) {
	uint32_t locks = atomic_load(&section_locks);
	uint32_t mask = (1 << BUFFER_SECTIONS) - 1;
	return locks & mask;
}

void lock_section(int sect) {
	uint32_t mask = 1U << sect;
	atomic_fetch_or(&section_locks, mask);
	if (DEBUG) {
		printf("locked s%d\n", sect);
	}
}

void unlock_section(int sect) {
	uint32_t mask = ~(1U << sect);
	atomic_fetch_and(&section_locks, mask);
	if (DEBUG) {
		printf("unlocked s%d\n", sect);
	}
}

bool is_section_locked(int sect) {
	uint32_t locks = atomic_load(&section_locks);
	uint32_t mask = 1U << sect;
	return (locks & mask) != 0;
}

static inline bool is_section_unlocked(int sect) {
	return !is_section_locked(sect);
}

void set_section_size(int sect, int nbytes) {
	atomic_store(&section_sizes[sect], (uint32_t) nbytes);
	if (DEBUG) {
		printf("new s%d size: %d bytes\n", sect, nbytes);
	}
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

bool __not_in_flash_func(flash_verify)(spi_inst_t *spi, uint cs_pin, uint32_t addr, const uint8_t *src, size_t len) {
	bool valid = true;

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
				uint8_t data = (uint8_t) spi_get_hw(spi)->dr;
				uint8_t want = *src++;
				if (valid && data != want) {
					valid = false;
					if (DEBUG) {
						printf("mismatch at position %d\n", len - rx_data_remaining);
						printf("want 0x%02" PRIx8 "; got 0x%02" PRIx8 "\n", want, data);
					}
				}
				--rx_data_remaining;
			}
		}
	}

	while (spi_get_hw(spi)->sr & SPI_SSPSR_BSY_BITS);
	asm volatile("nop \n nop \n nop");
	gpio_set_function(cs_pin, GPIO_FUNC_SPI);

	return valid;
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

void __not_in_flash_func(flash_aai_write)(spi_inst_t *spi, uint cs_pin, uint rx_pin, uint32_t addr, const uint8_t *src, size_t len) {
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

static inline uint32_t be_uint32(const uint8_t *src) {
	return ((uint32_t) src[0] << 24) |
		   ((uint32_t) src[1] << 16) |
		   ((uint32_t) src[2] << 8)  |
		   ((uint32_t) src[3]);
}

static inline uint16_t be_uint16(const uint8_t *src) {
	return ((uint32_t) src[0] << 8) |
		   ((uint32_t) src[1]);
}

void erase_ranges_blocking(spi_inst_t *spi, const erase_range_t *ranges, int range_count) {
	const uint32_t block_mask = 64 * 1024 - 1;
	uint32_t prev_end_addr = 0;

	for (int i = 0; i < range_count; ++i) {
		uint32_t start_addr = ranges[i].address & ~block_mask;
		uint32_t end_addr = ranges[i].address +
							ranges[i].sectors * FLASH_ERASE_SECTOR_SIZE;
		end_addr = (end_addr + block_mask) & ~block_mask;

		if (i > 0) {
			if (prev_end_addr >= end_addr) {
				continue;
			}
			if (prev_end_addr > start_addr) {
				start_addr = prev_end_addr;
			}
		}

		uint32_t block_addr = start_addr;
		while (block_addr < end_addr) {
			flash_erase(spi, FLASH_CMD_ERASE_64K_BLOCK, block_addr);
			if (DEBUG) {
				printf("64K erase at address: 0x%08" PRIx32 "\n", block_addr);
			}
			block_addr += 64 * 1024;
		}

		prev_end_addr = end_addr;
	}
}

int write_and_verify_blocking(spi_inst_t *spi, uint cs_pin, uint rx_pin, uint32_t addr, const uint8_t *src, size_t len) {
	int written = 0;

	if (DEBUG) {
		printf("writing %d bytes at address 0x%08" PRIx32 "\n", len, addr);
	}

	bool odd_addr = addr % 2 == 1;
	if (odd_addr) {
		flash_byte_write(spi0, addr, *src);
		if (DEBUG) {
			printf("wrote 0x%02" PRIx8 " at odd address 0x%08" PRIx32 "\n", *src, addr);
		}
		++addr;
		++src;
		++written;
	}
	if (written == len) return written;

	size_t aai_write_size = len - written;

	bool trailing_byte = aai_write_size % 2 == 1;
	if (trailing_byte) {
		--aai_write_size;
	}

	if (aai_write_size > 0) {
		flash_aai_write(
			spi0,
			SPI_CSN_PIN, SPI_RX_PIN,
			addr,
			src,
			aai_write_size
		);
		addr += aai_write_size;
		src += aai_write_size;
		written += aai_write_size;
	}

	if (trailing_byte) {
		flash_byte_write(spi0, addr, *src);
		if (DEBUG) {
			printf("wrote trailing byte 0x%02" PRIx8 " at address 0x%08" PRIx32 "\n", *src, addr);
		}
		++written;
	}
	if (DEBUG) {
		printf("wrote %d bytes\n", written);
	}
	return written;
}

void core1_entry() {
	gpio_set_dir(SPI_CSN_PIN, GPIO_OUT);
	gpio_put(SPI_CSN_PIN, 0);

	spi_init(spi0, 10 * 1000 * 1000);
	spi_set_format(spi0, 8, SPI_CPOL_1, SPI_CPHA_1, SPI_MSB_FIRST);
	gpio_set_function(SPI_SCK_PIN, GPIO_FUNC_SPI);
	gpio_set_function(SPI_TX_PIN, GPIO_FUNC_SPI);
	gpio_set_function(SPI_RX_PIN, GPIO_FUNC_SPI);
	gpio_set_function(SPI_CSN_PIN, GPIO_FUNC_SPI);

	sleep_ms(1);
	flash_unlock(spi0);

	bool got_eod = false;
	uint8_t got_err = 0x00;

	while (true) {
		if (is_section_unlocked(read_section)) {
			int sect = read_section;
			while (is_section_unlocked(sect)) {
				if (got_eod && read_locks() == 0) {
					if (tud_vendor_write_available()) {
						uint8_t resp = got_err ? got_err : RESP_SUCCESS;
						tud_vendor_write(&resp, 1);
						tud_vendor_write_flush();
						if (DEBUG) {
							printf("sent response: 0x%02" PRIx8 "\n", resp);
							printf("-----------------------------\n");
						}
						got_eod = false;
						got_err = 0x00;
					}
				}
				sect = (sect + 1) % BUFFER_SECTIONS;
				sleep_ms(1);
			}
			read_section = sect;
			read_sect_pos = 0;
			read_ptr = NULL;
		}

		if (read_ptr == NULL) {
			read_ptr = glob_buffer + (read_section * BUFFER_SECTION_SIZE) + read_sect_pos;
		}

		int remaining = get_section_size(read_section) - read_sect_pos;

		while (remaining > 0) {
			switch (*read_ptr) {
			case CMD_ERASE_RANGES:
				--remaining;
				++read_sect_pos;
				++read_ptr;
				if (remaining < 4) break;
				int range_count = (int) be_uint32(read_ptr);
				int body_size = 8 * range_count;
				remaining -= 4;
				read_sect_pos += 4;
				read_ptr += 4;
				if (remaining < body_size) break;
				erase_range_t *ranges = malloc(range_count * sizeof(erase_range_t));
				if (ranges == NULL) {
					if (DEBUG) {
						printf(
							"can't allocate %d ranges (%d bytes)\n",
							range_count,
							range_count * sizeof(erase_range_t)
						);
					}
					break;
				};
				for (int i = 0; i < range_count; ++i) {
					ranges[i].address = be_uint32(read_ptr);
					ranges[i].sectors = (int) be_uint32(read_ptr+4);
					read_ptr += 8;
				}
				erase_ranges_blocking(spi0, ranges, range_count);
				free(ranges);
				remaining -= body_size;
				read_sect_pos += body_size;
				while (!tud_vendor_write_available());
				uint8_t resp = RESP_SUCCESS;
				tud_vendor_write(&resp, 1);
				tud_vendor_write_flush();
				break;
			case CMD_DATA_SLICE:
				--remaining;
				++read_sect_pos;
				++read_ptr;
				if (DEBUG) {
					printf("started processing a data slice from s%d\n", read_section);
				}
				if (remaining < 6) break;
				uint32_t target_addr = be_uint32(read_ptr);
				int data_size = (int) be_uint16(read_ptr+4);
				remaining -= 6;
				read_sect_pos += 6;
				read_ptr += 6;
				if (remaining < data_size) {
					if (DEBUG) printf("remaining < data_size !!!\n");
					break;
				};
				write_and_verify_blocking(
					spi0,
					SPI_CSN_PIN, SPI_RX_PIN,
					target_addr,
					read_ptr,
					data_size
				);
				if (DEBUG) {
					printf("wrote complete, starting verification...\n");
				}
				bool valid = flash_verify(
					spi0,
					SPI_CSN_PIN,
					target_addr,
					read_ptr,
					data_size
				);
				if (got_err == 0x00 && !valid) {
					got_err = RESP_ERR_VERIFICATION;
				}
				if (DEBUG) {
					printf("64K verification: %s\n", valid ? "success" : "failure");
				}
				remaining -= data_size;
				read_sect_pos += data_size;
				read_ptr += data_size;
				break;
			case CMD_END_OF_DATA:
				--remaining;
				++read_sect_pos;
				++read_ptr;
				got_eod = true;
				break;
			default:
				--remaining;
				++read_sect_pos;
				++read_ptr;
				break;
			}
		}

		unlock_section(read_section);

		read_sect_pos = 0;
		read_ptr = NULL;
	}
}

int main(void) {
	board_init();
	tusb_rhport_init_t device_init = {
		.role = TUSB_ROLE_DEVICE,
		.speed = TUSB_SPEED_AUTO,
	};
	tusb_init(BOARD_TUD_RHPORT, &device_init);

	if (board_init_after_tusb) {
		board_init_after_tusb();
	}

	stdio_init_all();
	for (int i = 0; i < BUFFER_SECTIONS; ++i) {
		atomic_store(&section_sizes[i], 0);
	}
	multicore_launch_core1(core1_entry);

	while (true) {
		tud_task();
		auto_lock_task();
	}
}

void auto_lock_task(void) {
	if (rx_in_progress) return;
	if (is_nil_time(last_reception_time)) return;

	if (is_section_locked(write_section)) return;
	if (write_sect_pos == 0) return;

	if (absolute_time_diff_us(last_reception_time, get_absolute_time()) > 5e5) {
		set_section_size(write_section, write_sect_pos);
		lock_section(write_section);

		write_sect_pos = 0;
		write_ptr = NULL;
	}
}

void tud_mount_cb(void) {}
void tud_unmount_cb(void) {}

void tud_suspend_cb(bool remote_wakeup_en) {
	(void) remote_wakeup_en;
}
void tud_resume_cb(void) {}

void tud_vendor_rx_cb(uint8_t itf, const uint8_t *buffer, uint16_t bufsize) {
	(void) itf;

	rx_in_progress = true;
	int remaining = (int) bufsize;

	while (remaining > 0) {
		if (is_section_locked(write_section)) {
			int sect = write_section;
			while (is_section_locked(sect)) {
				sect = (sect + 1) % BUFFER_SECTIONS;
				sleep_ms(1);
			}
			write_section = sect;
			write_sect_pos = 0;
			write_ptr = NULL;
		}

		if (write_ptr == NULL) {
			write_ptr = glob_buffer + (write_section * BUFFER_SECTION_SIZE) + write_sect_pos;
		}

		int sect_remaining = BUFFER_SECTION_SIZE - write_sect_pos;
		if (sect_remaining > 0) {
			int cpy_size = (remaining < sect_remaining) ? remaining : sect_remaining;
			memcpy(write_ptr, buffer, cpy_size);
			buffer += cpy_size;
			remaining -= cpy_size;
			write_sect_pos += cpy_size;
			write_ptr += cpy_size;
		} else {
			set_section_size(write_section, BUFFER_SECTION_SIZE);
			lock_section(write_section);

			write_sect_pos = 0;
			write_ptr = NULL;
		}
	}

#if CFG_TUD_VENDOR_RX_BUFSIZE > 0
	tud_vendor_read_flush();
#endif

	last_reception_time = get_absolute_time();
	rx_in_progress = false;
}
