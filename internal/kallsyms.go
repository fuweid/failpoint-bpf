package internal

import (
	"bufio"
	"bytes"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"strings"
	"sync"
)

var syscallSyms struct {
	sync.Mutex

	loadErr error
	symbols map[string]uint64
}

// SyscallAddress returns syscall's address.
func SyscallAddress(syscall string) (uint64, error) {
	syscallSyms.Lock()
	defer syscallSyms.Unlock()

	if syscallSyms.loadErr != nil {
		return 0, syscallSyms.loadErr
	}

	if len(syscallSyms.symbols) == 0 {
		syscallSyms.symbols, syscallSyms.loadErr = loadSyscallSyms()
		if syscallSyms.loadErr != nil {
			return 0, syscallSyms.loadErr
		}
	}

	addr, ok := syscallSyms.symbols[syscall]
	if !ok {
		return 0, fmt.Errorf("no such syscall symbol %s", syscall)
	}
	return addr, nil
}

func loadSyscallSyms() (map[string]uint64, error) {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc/kallsyms: %w", err)
	}
	defer f.Close()

	symbols := make(map[string]uint64)

	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := scan.Bytes()

		fields := bytes.Fields(line)
		if len(fields) < 3 {
			continue
		}

		if string(fields[1]) != "T" {
			continue
		}

		addrInt := new(big.Int)
		addrInt.SetString(string(fields[0]), 16)

		symbol := string(fields[2])
		switch runtime.GOARCH {
		case "amd64":
			if !strings.HasPrefix(symbol, "__x64_sys_") {
				continue
			}

			symbols[strings.TrimPrefix(symbol, "__x64_sys_")] = addrInt.Uint64()
		default:
			return nil, fmt.Errorf("not supported yet")
		}
	}
	if scan.Err() != nil {
		return nil, scan.Err()
	}
	return symbols, nil
}
