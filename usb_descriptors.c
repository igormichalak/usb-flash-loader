#include "bsp/board_api.h"
#include "tusb.h"

#define USB_PID 0xE18A
#define USB_VID 0xCAFE
#define USB_BCD 0x0200

//-------------------------------------------------------+
// Device Descriptors
//-------------------------------------------------------+

const tusb_desc_device_t desc_device = {
	.bLength			= sizeof(tusb_desc_device_t),
	.bDescriptorType	= TUSB_DESC_DEVICE,
	.bcdUSB				= USB_BCD,
	.bDeviceClass		= TUSB_CLASS_VENDOR_SPECIFIC,
	.bDeviceSubClass	= 0x00,
	.bDeviceProtocol	= 0x00,
	.bMaxPacketSize0	= CFG_TUD_ENDPOINT0_SIZE,
	.idVendor			= USB_VID,
	.idProduct			= USB_PID,
	.bcdDevice			= 0x0100,
	.iManufacturer		= 0x01,
	.iProduct			= 0x02,
	.iSerialNumber		= 0x03,
	.bNumConfigurations	= 0x01,
};

const uint8_t *tud_descriptor_device_cb(void) {
	return (const uint8_t *) &desc_device;
}

//-------------------------------------------------------+
// Configuration Descriptor
//-------------------------------------------------------+

enum {
	ITF_NUM_VENDOR = 0,
	ITF_NUM_TOTAL,
};

#define CONFIG_TOTAL_LEN (TUD_CONFIG_DESC_LEN + TUD_VENDOR_DESC_LEN)

#define EPNUM_VENDOR_OUT	0x01
#define EPNUM_VENDOR_IN		0x81

const uint8_t desc_fs_configuration[] = {
	TUD_CONFIG_DESCRIPTOR(1, ITF_NUM_TOTAL, 0, CONFIG_TOTAL_LEN, 0x00, 100),
	TUD_VENDOR_DESCRIPTOR(ITF_NUM_VENDOR, 4, EPNUM_VENDOR_OUT, EPNUM_VENDOR_IN, 64),
};

#if TUD_OPT_HIGH_SPEED

const uint8_t desc_hs_configuration[] = {
	TUD_CONFIG_DESCRIPTOR(1, ITF_NUM_TOTAL, 0, CONFIG_TOTAL_LEN, 0x00, 100),
	TUD_VENDOR_DESCRIPTOR(ITF_NUM_VENDOR, 4, EPNUM_VENDOR_OUT, EPNUM_VENDOR_IN, 512),
};

const tusb_desc_device_qualifier_t desc_device_qualifier = {
	.bLength			= sizeof(tusb_desc_device_t),
	.bDescriptorType	= TUSB_DESC_DEVICE,
	.bcdUSB				= USB_BCD,
	.bDeviceClass		= TUSB_CLASS_VENDOR_SPECIFIC,
	.bDeviceSubClass	= 0x00,
	.bDeviceProtocol	= 0x00,
	.bMaxPacketSize0	= CFG_TUD_ENDPOINT0_SIZE,
	.bNumConfigurations	= 0x01,
	.bReserved			= 0x00,
};

const uint8_t *tud_descriptor_device_qualifier_cb(void) {
	return (const uint8_t *) &desc_device_qualifier;
}

const uint8_t *tud_descriptor_other_speed_configuration_cb(uint8_t index) {
	(void) index;
	return (tud_speed_get() == TUSB_SPEED_HIGH) ? desc_fs_configuration : desc_hs_configuration;
}

#endif /* TUD_OPT_HIGH_SPEED */

const uint8_t *tud_descriptor_configuration_cb(uint8_t index) {
	(void) index;

#if TUD_OPT_HIGH_SPEED
	return (tud_speed_get() == TUSB_SPEED_HIGH) ? desc_hs_configuration : desc_fs_configuration;
#else
	return desc_fs_configuration;
#endif
};

//-------------------------------------------------------+
// String Descriptors
//-------------------------------------------------------+

enum {
	STRID_LANGID = 0,
	STRID_MANUFACTURER,
	STRID_PRODUCT,
	STRID_SERIAL,
};

const char *string_desc_arr[] = {
	(const char[]){ 0x09, 0x04 },
	"OSHW",
	"SPI Flash Programmer",
	NULL,
	"Vendor Interface",
};

static uint16_t _desc_str[32+1];

const uint16_t *tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
	(void) langid;
	size_t chr_count;

	switch (index) {
	case STRID_LANGID:
		memcpy(&_desc_str[1], string_desc_arr[0], 2);
		chr_count = 1;
		break;
	case STRID_SERIAL:
		chr_count = board_usb_get_serial(_desc_str + 1, 32);
		break;
	default:
		if (!(index < sizeof(string_desc_arr) / sizeof(string_desc_arr[0]))) return NULL;

		const char *str = string_desc_arr[index];

		chr_count = strlen(str);
		const size_t max_count = sizeof(_desc_str) / sizeof(_desc_str[0]) - 1;
		if (chr_count > max_count) chr_count = max_count;

		for (size_t i = 0; i < chr_count; i++) {
			_desc_str[1 + i] = str[i];
		}
		break;
	}

	_desc_str[0] = (uint16_t) ((TUSB_DESC_STRING << 8) | (2 * chr_count + 2));

	return _desc_str;
}
