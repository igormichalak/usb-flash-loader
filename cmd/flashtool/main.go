package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/gousb"
)

type AlignedFile struct {
	Alignment int
	Path      string
}

type WriteGroup struct {
	Offset int
	Files  []AlignedFile
}

func matchFlag(s string, flagNames ...string) bool {
	hyphens := 0
	for _, c := range s {
		if c == '-' {
			hyphens++
		} else {
			break
		}
	}
	if hyphens == 0 || hyphens > 2 {
		return false
	}
	return slices.Contains(flagNames, s[hyphens:])
}

func parseOffset(s string) (int, error) {
	var n int64
	var err error
	switch true {
	case strings.HasPrefix(s, "0x"):
		if utf8.RuneCountInString(s) == 2 {
			return 0, fmt.Errorf("offset consists only of a hex prefix")
		}
		n, err = strconv.ParseInt(s[2:], 16, 64)
	case strings.HasPrefix(s, "0") && utf8.RuneCountInString(s) > 1:
		n, err = strconv.ParseInt(s[1:], 8, 64)
	case strings.HasPrefix(s, "0b"):
		if utf8.RuneCountInString(s) == 2 {
			return 0, fmt.Errorf("offset consists only of a binary prefix")
		}
		n, err = strconv.ParseInt(s[2:], 2, 64)
	default:
		n, err = strconv.ParseInt(s, 10, 64)
	}
	if err != nil {
		return 0, fmt.Errorf("cannot parse the offset value: %w", err)
	}
	if n < 0 {
		return 0, fmt.Errorf("offset cannot be negative")
	}
	if n > math.MaxInt32 {
		return 0, fmt.Errorf("offset has to be 32-bit")
	}
	return int(n), nil
}

func parseArgs(args []string) ([]WriteGroup, error) {
	var groups []WriteGroup
	var wg *WriteGroup
	currentAlignment := 1

	for i := 0; i < len(args); i++ {
		if matchFlag(args[i], "debug", "erase-sector") {
			i++
			continue
		}
		if matchFlag(args[i], "o", "p2a", "f") && i == len(args)-1 {
			return nil, fmt.Errorf("no value given for %q", args[i])
		}
		switch true {
		case matchFlag(args[i], "o"):
			if wg != nil {
				groups = append(groups, *wg)
			}
			offset, err := parseOffset(args[i+1])
			if err != nil {
				return nil, err
			}
			wg = &WriteGroup{
				Offset: offset,
				Files:  make([]AlignedFile, 0),
			}
			currentAlignment = 1
			i++
		case matchFlag(args[i], "p2a"):
			if wg == nil {
				return nil, fmt.Errorf("%q has to be preceded by an offset flag (-o)")
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil {
				return nil, fmt.Errorf("cannot parse %q flag value: %s", args[i], args[i+1])
			}
			currentAlignment = 1 << n
			i++
		case matchFlag(args[i], "f"):
			if wg == nil {
				return nil, fmt.Errorf("%q has to be preceded by an offset flag (-o)")
			}
			wg.Files = append(wg.Files, AlignedFile{
				Alignment: currentAlignment,
				Path: args[i+1],
			})
			i++
		}
	}
	if wg != nil {
		groups = append(groups, *wg)
	}
	return groups, nil
}

func isFile(path string) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		var pathErr *fs.PathError
		if errors.As(err, &pathErr) {
			return false, nil
		} else {
			return false, err
		}
	}
	return !fi.IsDir(), nil
}

func verifyFiles(groups []WriteGroup) error {
	for _, group := range groups {
		for _, file := range group.Files {
			if ok, err := isFile(file.Path); err != nil {
				return err
			} else if !ok {
				printPath := file.Path
				absolutePath, err := filepath.Abs(file.Path)
				if err == nil {
					printPath = absolutePath
				}
				return fmt.Errorf("%q is not a file", printPath)
			}
		}
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Printf("Error: %v\n", err)
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

	if *debug < 0 || *debug > 3 {
		return fmt.Errorf("debug level out of range (0..3)")
	}

	groups, err := parseArgs(os.Args[1:])
	if err != nil {
		return err
	}
	if err := verifyFiles(groups); err != nil {
		return err
	}

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
