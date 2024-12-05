package main

import (
	"bytes"
	"context"
	"encoding/binary"
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
	"time"
	"unicode/utf8"

	"github.com/google/gousb"
)

const EraseSectorInBytes = 4096

var EraseSizesDesc = []int{64 * 1024, 32 * 1024, 4 * 1024}

const (
	CMD_ERASE_RANGES = 0x01
	CMD_DATA_SLICE   = 0x02
	CMD_END_OF_DATA  = 0x03
)

type AlignedFile struct {
	Alignment int
	Path      string
}

type WriteGroup struct {
	MemOffset int
	Files     []AlignedFile
}

type FlashChunk struct {
	MemOffset int
	MemSize   int
	Data      []byte
}

type FileMapping struct {
	Path      string
	MemOffset int
	MemSize   int
}

type EraseRange struct {
	Address int
	Sectors int
}

func (r *EraseRange) end() int {
	return r.Address + r.Sectors*EraseSectorInBytes
}

func log2Int(n int) int {
	if n <= 0 {
		return -1
	}
	log := 0
	for n > 1 {
		n >>= 1
		log++
	}
	return log
}

// func parseMemSize(s string) (int, error) {
// 	multiplier := 1
// 	lc, lcn := utf8.DecodeLastRuneInString(s)
// 	switch lc {
// 	case 'K':
// 		multiplier = 1024
// 		s = s[:len(s)-lcn]
// 	case 'M':
// 		multiplier = 1024 * 1024
// 		s = s[:len(s)-lcn]
// 	default:
// 		if !unicode.IsDigit(lc) {
// 			return 0, fmt.Errorf("invalid suffix: %q", lc)
// 		}
// 	}
// 	n, err := strconv.Atoi(s)
// 	if err != nil {
// 		return 0, fmt.Errorf("can't parse mem size: %w", err)
// 	}
// 	if n > (math.MaxInt / multiplier) {
// 		return 0, fmt.Errorf("mem size overflow: %d * %d", n, multiplier)
// 	}
// 	return n * multiplier, nil
// }

// func parseEraseBlocks(s string) ([]int, error) {
// 	var sizes []int
// 	for _, memSize := range strings.Split(s, ",") {
// 		n, err := parseMemSize(memSize)
// 		if err != nil {
// 			return nil, err
// 		}
// 		sizes = append(sizes, n)
// 	}
// 	return sizes, nil
// }

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

func parseMemOffset(s string) (int, error) {
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
		if matchFlag(args[i], "o", "a", "p2a", "f") && i == len(args)-1 {
			return nil, fmt.Errorf("no value given for %q", args[i])
		}
		switch true {
		case matchFlag(args[i], "o"):
			if wg != nil && len(wg.Files) > 0 {
				groups = append(groups, *wg)
			}
			offset, err := parseMemOffset(args[i+1])
			if err != nil {
				return nil, err
			}
			wg = &WriteGroup{
				MemOffset: offset,
				Files:     make([]AlignedFile, 0),
			}
			currentAlignment = 1
			i++
		case matchFlag(args[i], "a"):
			if wg == nil {
				return nil, fmt.Errorf("%q has to be preceded by an offset flag (-o)", args[i])
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil {
				return nil, fmt.Errorf("cannot parse %q flag value: %s", args[i], args[i+1])
			}
			currentAlignment = n
			i++
		case matchFlag(args[i], "p2a"):
			if wg == nil {
				return nil, fmt.Errorf("%q has to be preceded by an offset flag (-o)", args[i])
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil {
				return nil, fmt.Errorf("cannot parse %q flag value: %s", args[i], args[i+1])
			}
			currentAlignment = 1 << n
			i++
		case matchFlag(args[i], "f"):
			if wg == nil {
				return nil, fmt.Errorf("%q has to be preceded by an offset flag (-o)", args[i])
			}
			wg.Files = append(wg.Files, AlignedFile{
				Alignment: currentAlignment,
				Path:      args[i+1],
			})
			i++
		default:
			return nil, fmt.Errorf("unrecognized flag: %s", args[i])
		}
	}
	if wg != nil && len(wg.Files) > 0 {
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

func generateFlashChunks(groups []WriteGroup) ([]FlashChunk, []FileMapping, error) {
	var chunks []FlashChunk
	var mappings []FileMapping
	buf := bytes.NewBuffer(make([]byte, 0, 1024))
	prevGroupEnd := 0
	for _, group := range groups {
		currentMemOffset := group.MemOffset
		if currentMemOffset < prevGroupEnd {
			return nil, nil, fmt.Errorf(
				"write group starting at offset %#x overlaps with "+
					"previous write group ending at %#x",
				currentMemOffset, prevGroupEnd,
			)
		}
		for _, af := range group.Files {
			pads := (af.Alignment - (currentMemOffset % af.Alignment)) % af.Alignment
			for i := 0; i < pads; i++ {
				if err := buf.WriteByte(0); err != nil {
					return nil, nil, fmt.Errorf("can't pad data: %w", err)
				}
			}
			currentMemOffset += pads
			f, err := os.Open(af.Path)
			if err != nil {
				return nil, nil, fmt.Errorf("can't open a file: %w", err)
			}
			n, err := f.WriteTo(buf)
			f.Close()
			if err != nil {
				return nil, nil, fmt.Errorf("can't copy data from file %s to buffer: %w", af.Path, err)
			}
			mappings = append(mappings, FileMapping{
				Path:      af.Path,
				MemOffset: currentMemOffset,
				MemSize:   int(n),
			})
			currentMemOffset += int(n)
		}
		data := make([]byte, buf.Len())
		copy(data, buf.Bytes())
		buf.Reset()
		chunks = append(chunks, FlashChunk{
			MemOffset: group.MemOffset,
			MemSize:   currentMemOffset - group.MemOffset,
			Data:      data,
		})
		prevGroupEnd = currentMemOffset
	}
	slices.SortFunc(chunks, func(a, b FlashChunk) int {
		return a.MemOffset - b.MemOffset
	})
	slices.SortFunc(mappings, func(a, b FileMapping) int {
		return a.MemOffset - b.MemOffset
	})
	return chunks, mappings, nil
}

func calculateEraseRanges(chunks []FlashChunk) []EraseRange {
	var ranges []EraseRange
	for _, chunk := range chunks {
		if chunk.MemSize == 0 {
			continue
		}
		startAddress := chunk.MemOffset &^ (EraseSectorInBytes - 1)
		endAddress := chunk.MemOffset + chunk.MemSize
		if endAddress%EraseSectorInBytes != 0 {
			endAddress = (endAddress + EraseSectorInBytes - 1) &^ (EraseSectorInBytes - 1)
		}
		sectors := (endAddress - startAddress) >> log2Int(EraseSectorInBytes)
		ranges = append(ranges, EraseRange{
			Address: startAddress,
			Sectors: sectors,
		})
	}
	slices.SortFunc(ranges, func(a, b EraseRange) int {
		return a.Address - b.Address
	})
	return mergeEraseRanges(ranges)
}

func mergeEraseRanges(ranges []EraseRange) []EraseRange {
	if len(ranges) == 0 {
		return nil
	}
	var merged []EraseRange
	current := ranges[0]
	for _, r := range ranges[1:] {
		if r.Address <= current.end() {
			current.Sectors = (r.end() - current.Address) / EraseSectorInBytes
		} else {
			merged = append(merged, current)
			current = r
		}
	}
	merged = append(merged, current)
	return merged
}

func transmitEraseRanges(
	ctx context.Context,
	epOut *gousb.OutEndpoint,
	epIn *gousb.InEndpoint,
	ranges []EraseRange,
) error {
	respC := make(chan error)
	go func() {
		defer close(respC)
		buf := make([]byte, epIn.Desc.MaxPacketSize)
		n, err := epIn.ReadContext(ctx, buf)
		if err != nil {
			respC <- fmt.Errorf("failed to read response: %w", err)
		} else if n != 1 {
			respC <- fmt.Errorf("invalid response length: %d", n)
		} else if buf[0] == 0x00 {
			respC <- nil
		} else {
			respC <- fmt.Errorf("unrecognized error (%#02x)", buf[0])
		}
	}()

	totalBytes := 5 + len(ranges)*8
	msg := make([]byte, totalBytes)
	msg[0] = CMD_ERASE_RANGES
	binary.BigEndian.PutUint32(msg[1:5], uint32(len(ranges)))

	for i, r := range ranges {
		pos := 5 + i*8
		binary.BigEndian.PutUint32(msg[pos:pos+4], uint32(r.Address))
		binary.BigEndian.PutUint32(msg[pos+4:pos+8], uint32(r.Sectors))
	}

	if _, err := epOut.WriteContext(ctx, msg); err != nil {
		return err
	}

	return <-respC
}

func transmitChunks(
	ctx context.Context,
	epOut *gousb.OutEndpoint,
	epIn *gousb.InEndpoint,
	chunks []FlashChunk,
) error {
	respC := make(chan error)
	go func() {
		defer close(respC)
		buf := make([]byte, epIn.Desc.MaxPacketSize)
		n, err := epIn.ReadContext(ctx, buf)
		if err != nil {
			respC <- fmt.Errorf("failed to read response: %w", err)
		} else if n != 1 {
			respC <- fmt.Errorf("invalid response length: %d", n)
		} else if buf[0] == 0x00 {
			respC <- nil
		} else {
			respC <- fmt.Errorf("unrecognized error (%#02x)", buf[0])
		}
	}()

	PS := epOut.Desc.MaxPacketSize
	const bufSize = 64 * 1024
	const headerSize = 7 // cmd (1 byte) + offset (4 bytes) + length (2 bytes)

	queueSize := bufSize / PS
	stream, err := epOut.NewStream(PS, queueSize)
	if err != nil {
		return err
	}

	buf := make([]byte, bufSize)
	pos := 0

	for _, chunk := range chunks {
		offset := 0
		for offset < chunk.MemSize {
			dataLen := chunk.MemSize - offset
			bufAvailable := bufSize - pos

			if headerSize+min(dataLen, 64) > bufAvailable {
				for i := 0; i < bufAvailable; i++ {
					buf[pos] = 0x00
					pos++
				}
				_, err := stream.WriteContext(ctx, buf)
				if err != nil {
					return err
				}
				pos = 0
				bufAvailable = bufSize
			}

			if headerSize+dataLen > bufAvailable {
				dataLen = bufAvailable - headerSize
			}

			buf[pos] = CMD_DATA_SLICE
			binary.BigEndian.PutUint32(buf[pos+1:pos+5], uint32(chunk.MemOffset+offset))
			binary.BigEndian.PutUint16(buf[pos+5:pos+7], uint16(dataLen))
			pos += headerSize
			copy(buf[pos:pos+dataLen], chunk.Data[offset:offset+dataLen])
			pos += dataLen
			offset += dataLen
		}
	}

	finalCmdSent := false

	if pos > 0 {
		pads := (PS - (pos % PS)) % PS
		if pads > 0 {
			buf[pos] = CMD_END_OF_DATA
			pos++
			pads--
			finalCmdSent = true
		}
		for i := 0; i < pads; i++ {
			buf[pos] = 0x00
			pos++
		}
		_, err := stream.WriteContext(ctx, buf[:pos])
		if err != nil {
			return err
		}
		pos = 0
	}

	if !finalCmdSent {
		buf[pos] = CMD_END_OF_DATA
		pos++
		for i := 1; i < PS; i++ {
			buf[pos] = 0x00
			pos++
		}
		_, err := stream.WriteContext(ctx, buf[:PS])
		if err != nil {
			return err
		}
	}

	if err := stream.CloseContext(ctx); err != nil {
		return err
	}

	return <-respC
}

func printFileMappings(mappings []FileMapping) {
	fmt.Println("File mappings:")
	highestOffset := 0
	for _, mapping := range mappings {
		highestOffset = max(highestOffset, mapping.MemOffset)
	}
	hexDigits := 1
	if highestOffset > 0 {
		hexDigits = int(math.Ceil(math.Log2(float64(highestOffset)) / 4))
	}
	offsetFormat := fmt.Sprintf("%%#0%dx", hexDigits)
	for _, mapping := range mappings {
		fmt.Printf(offsetFormat, mapping.MemOffset)
		fmt.Printf(" <-> %s (%d bytes)\n", mapping.Path, mapping.MemSize)
	}
}

func formatMemSize(n int) string {
	var postfix string
	if n%(1024*1024) == 0 {
		n /= 1024 * 1024
		postfix = "M"
	} else if n%1024 == 0 {
		n /= 1024
		postfix = "K"
	}
	return strconv.Itoa(n) + postfix
}

func padLeft(s string, length int) string {
	if len(s) >= length {
		return s
	}
	padding := strings.Repeat(" ", length-len(s))
	return padding + s
}

func count64KBlocks(ranges []EraseRange) int {
	n := 0
	prevEndAddress := 0
	for i, r := range ranges {
		startAddress := r.Address &^ (64*1024 - 1)
		endAddress := (r.end() + 64*1024 - 1) &^ (64*1024 - 1)

		if i > 0 {
			if prevEndAddress >= endAddress {
				continue
			}
			if prevEndAddress > startAddress {
				startAddress = prevEndAddress
			}
		}

		n += (endAddress - startAddress) >> log2Int(64*1024)
		prevEndAddress = endAddress
	}
	return n
}

func printEraseSummary(ranges []EraseRange) {
	m := make(map[int]int, len(EraseSizesDesc))
	m[64*1024] = count64KBlocks(ranges)
	type summaryRow struct {
		Count string
		Size  string
	}
	var rows []summaryRow
	for _, size := range EraseSizesDesc {
		count, ok := m[size]
		if !ok {
			continue
		}
		rows = append(rows, summaryRow{
			Count: strconv.Itoa(count),
			Size:  formatMemSize(size),
		})
	}
	labelCount := "Block count"
	labelSize := "Block size"
	maxLenCount := len(labelCount)
	maxLenSize := len(labelSize)
	for _, row := range rows {
		maxLenCount = max(maxLenCount, len(row.Count))
		maxLenSize = max(maxLenSize, len(row.Size))
	}
	fmt.Println("Erasure summary:")
	fmt.Printf(
		" %s | %s \n",
		padLeft(labelCount, maxLenCount),
		padLeft(labelSize, maxLenSize),
	)
	fmt.Println(strings.Repeat("-", 1+maxLenCount+3+maxLenSize+1))
	for _, row := range rows {
		fmt.Printf(
			" %s | %s \n",
			padLeft(row.Count, maxLenCount),
			padLeft(row.Size, maxLenSize),
		)
	}
}

func formatDuration(d time.Duration) string {
	if d.Seconds() >= 1 {
		return fmt.Sprintf("%.2f s", float64(d.Milliseconds())/1e3)
	}
	if d.Milliseconds() >= 1 {
		return fmt.Sprintf("%.2f ms", float64(d.Microseconds())/1e3)
	}
	return fmt.Sprintf("%d μs", d.Microseconds())
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
	// eraseBlocks := flag.String("erase-blocks", "4K,32K,64K", "erase block size list (e.g. 2048,4K,1M)")
	_ = flag.String("o", "", "offset (hex: 0x, octal: 0, binary: 0b or decimal literal)")
	_ = flag.Int("a", 0, "alignment (pad with 0s up to a multiple of N)")
	_ = flag.Int("p2a", 0, "power of two alignment (pad with 0s up to a multiple of 2^N)")
	_ = flag.String("f", "", "file to flash")
	flag.Usage = func() {
		fmt.Printf("Usage: %s -o <offset> -f <file> [-f <file> ...] [-o <offset> -f <file> ...]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *debug < 0 || *debug > 3 {
		return fmt.Errorf("debug level out of range (0..3)")
	}

	// eraseBlocksInBytes, err := parseEraseBlocks(*eraseBlocks)
	// if err != nil {
	// 	return fmt.Errorf("erase blocks: %w", err)
	// }
	// if len(eraseBlocksInBytes) == 0 {
	// 	return fmt.Errorf("at least one erase block size is required")
	// }
	// fmt.Printf("Smallest erase block size: %d byte(s).\n", slices.Min(eraseBlocksInBytes))

	groups, err := parseArgs(os.Args[1:])
	if err != nil {
		return err
	}
	if err := verifyFiles(groups); err != nil {
		return err
	}
	chunks, mappings, err := generateFlashChunks(groups)
	if err != nil {
		return err
	}
	if len(mappings) > 0 {
		printFileMappings(mappings)
	}
	eraseRanges := calculateEraseRanges(chunks)
	if len(eraseRanges) > 0 {
		printEraseSummary(eraseRanges)
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
	epOut, err := itf.OutEndpoint(0x01)
	if err != nil {
		return fmt.Errorf("%s.OutEndpoint(0x01): %w", itf, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fmt.Println("Erasing...")
	start := time.Now()
	err = transmitEraseRanges(ctx, epOut, epIn, eraseRanges)
	if err != nil {
		return fmt.Errorf("transmitEraseRanges(): %w", err)
	}
	fmt.Printf("Success after %s.\n", formatDuration(time.Since(start)))

	fmt.Println("Writing...")
	start = time.Now()
	err = transmitChunks(ctx, epOut, epIn, chunks)
	if err != nil {
		return fmt.Errorf("transmitChunks(): %w", err)
	}
	fmt.Printf("Success after %s.\n", formatDuration(time.Since(start)))

	return nil
}
