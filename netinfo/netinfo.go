
package netinfo

import (
	"encoding/binary"
	"fmt"
	"os"
	"regexp"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Endpoint struct {
	PID  uint32
	IP   string
	Port uint16
}


type TCPTableSource interface {
	Read() ([]Endpoint, error)
}


var Source TCPTableSource = windowsTCPTable{}

func LiveEndpoints(pids map[uint32]bool) ([]Endpoint, error) {
	all, err := Source.Read()
	if err != nil {
		return nil, err
	}

	var matched []Endpoint
	for _, e := range all {
		if pids[e.PID] && e.IP != "0.0.0.0" {
			matched = append(matched, e)
		}
	}
	return matched, nil
}


var ipv4Pattern = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)


func ScanFileForIPv4(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	seen := make(map[string]bool)
	var ips []string
	for _, m := range ipv4Pattern.FindAll(data, -1) {
		ip := string(m)
		if !seen[ip] && !isNoise(ip) {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

func isNoise(ip string) bool {
	return ip == "0.0.0.0"
}



var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCPTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	afINET                = 2
	tcpTableOwnerPIDAll   = 5 
	errInsufficientBuffer = 122
)


const tcpRowSize = 24

type windowsTCPTable struct{}


func (windowsTCPTable) Read() ([]Endpoint, error) {
	var size uint32
	ret, _, _ := procGetExtendedTCPTable.Call(
		0, uintptr(unsafe.Pointer(&size)), 0, afINET, tcpTableOwnerPIDAll, 0,
	)
	if ret != errInsufficientBuffer {
		return nil, fmt.Errorf("GetExtendedTcpTable size query failed: %d", ret)
	}

	buf := make([]byte, size)
	ret, _, _ = procGetExtendedTCPTable.Call(
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, afINET, tcpTableOwnerPIDAll, 0,
	)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable failed: %d", ret)
	}

	return parseTCPTable(buf), nil
}


func parseTCPTable(buf []byte) []Endpoint {
	if len(buf) < 4 {
		return nil
	}
	numEntries := binary.LittleEndian.Uint32(buf[0:4])

	var endpoints []Endpoint
	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + i*tcpRowSize
		if int(offset+tcpRowSize) > len(buf) {
			break
		}
		row := buf[offset : offset+tcpRowSize]

		endpoints = append(endpoints, Endpoint{
			IP:   ipFromBytes(row[12:16]),
			Port: portFromBytes(row[16:20]),
			PID:  binary.LittleEndian.Uint32(row[20:24]),
		})
	}
	return endpoints
}


func ipFromBytes(b []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

func portFromBytes(b []byte) uint16 {
	return uint16(b[0])<<8 | uint16(b[1])
}
