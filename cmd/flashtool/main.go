package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/google/gousb"
)

func main() {
	if err := run(); err != nil {
		fmt.Println(err)
		fmt.Println("Write failed.")
		os.Exit(1)
	}
	fmt.Println("Wrote successfully.")
}

func run() error {
	debug := flag.Int("debug", 0, "libusb debug level (0..3)")
	// eraseSector := flag.String("erase-sector", "", "min erase sector size (e.g. 2048, 4K, 1M)")
	_ = flag.String("o", "", "offset (hex: 0x, octal: 0, binary: 0b or decimal literal)")
	_ = flag.Int("p2a", 0, "power of two alignment (pad with 0s up to 2^N)")
	_ = flag.String("f", "", "file to flash")
	flag.Usage = func() {
		fmt.Printf("Usage: %s -o <offset> -f <file> [-f <file> ...] [-o <offset> -f <file> ...]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	usbctx := gousb.NewContext()
	defer usbctx.Close()

	usbctx.Debug(*debug)

	vid, pid := gousb.ID(0xCAFE), gousb.ID(0xE18A)

	dev, err := usbctx.OpenDeviceWithVIDPID(vid, pid)
	if err != nil {
		return fmt.Errorf("Could not open a device: %w", err)
	}
	if dev == nil {
		return fmt.Errorf("No matching device found.")
	}
	defer dev.Close()

	itf, done, err := dev.DefaultInterface()
	if err != nil {
		return fmt.Errorf("%s.DefaultInterface(): %w", dev, err)
	}
	defer done()

	epIn, err := itf.InEndpoint(0x81)
	if err != nil {
		return fmt.Errorf("%s.InEndpoint(0x81): %w", itf, err)
	}
	// epOut, err := itf.OutEndpoint(0x01)
	// if err != nil {
	// 	return fmt.Errorf("%s.OutEndpoint(0x01): %w", itf, err)
	// }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	respC := make(chan error)

	go func() {
		buf := make([]byte, epIn.Desc.MaxPacketSize)
		n, err := epIn.ReadContext(ctx, buf)
		if err != nil {
			respC <- fmt.Errorf("failed to read response: %w", err)
		} else if n != 1 {
			respC <- fmt.Errorf("invalid response length: %d", n)
		} else if buf[0] == 0x00 {
			respC <- nil
		} else {
			respC <- fmt.Errorf("unrecognized error (%#02X)", buf[0])
		}
	}()

	return <-respC
}
