//go:build windows

// Package netinfo finds the attacker's IP address two ways: reading the
// live TCP connection table for the target's processes, and regex-scanning
// the target's own executable bytes for IPv4 strings. The second way is
// what finds the attacker when the malware isn't currently connected.
package netinfo

import (
	"encoding/binary"
	"fmt"
	"os"
	"regexp"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Endpoint is one remote TCP connection, attributed to the PID that owns it.
type Endpoint struct {
	PID  uint32
	IP   string
	Port uint16
}

// TCPTableSource abstracts "give me the system's current TCP connection
// table." The real implementation calls the GetExtendedTcpTable syscall;
// tests or future platforms can swap in something else without touching
// the filtering logic in LiveEndpoints.
type TCPTableSource interface {
	Read() ([]Endpoint, error)
}

// Source is the TCP table source LiveEndpoints uses. It's a package
// variable, not a hardcoded call, so it can be swapped out.
var Source TCPTableSource = windowsTCPTable{}

// LiveEndpoints returns the remote address of every live TCP connection
// owned by one of the given PIDs. A remote IP of 0.0.0.0 means the socket
// is only listening, not connected out, so those are skipped.
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

// ipv4Pattern matches dotted-decimal IPv4 strings. It's deliberately loose
// (it doesn't reject e.g. 999.999.999.999) — the goal is to catch every
// candidate string in the binary, not to validate them.
var ipv4Pattern = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)

// ScanFileForIPv4 reads a file's raw bytes and regex-scans them for IPv4
// strings. Malware that talks to a hardcoded C2 address usually has that
// address sitting in the binary as plain ASCII, even when nothing is
// currently connected to it.
func ScanFileForIPv4(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	seen := make(map[string]bool)
	var ips []string
	for _, m := range ipv4Pattern.FindAll(data, -1) {
		ip := string(m)
		if !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

// --- windowsTCPTable: the real TCPTableSource, backed by GetExtendedTcpTable ---

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCPTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	afINET                = 2 // AF_INET
	tcpTableOwnerPIDAll   = 5 // TCP_TABLE_OWNER_PID_ALL
	errInsufficientBuffer = 122
)

// tcpRowSize is sizeof(MIB_TCPROW_OWNER_PID): five DWORDs plus the owning
// PID, 24 bytes, all read by hand below rather than overlaid with an
// unsafe-cast struct.
const tcpRowSize = 24

type windowsTCPTable struct{}

// Read calls GetExtendedTcpTable, first to learn the buffer size it needs
// and then again to fill it, which is the documented two-call pattern for
// this API since the table size varies with how many connections exist.
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

// parseTCPTable walks the MIB_TCPTABLE_OWNER_PID buffer by hand: a
// four-byte entry count, followed by that many fixed-size rows.
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

// ipFromBytes reads a MIB_TCPROW_OWNER_PID address field. Windows stores
// the four IP octets in order, so they can be read straight off as-is.
func ipFromBytes(b []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

// portFromBytes reads a MIB_TCPROW_OWNER_PID port field. Despite the field
// being a 4-byte DWORD, Windows only fills the low two bytes, and it does
// so in network (big-endian) byte order — the reverse of the DWORD's own
// little-endian storage — so the port is the first two bytes read in order.
func portFromBytes(b []byte) uint16 {
	return uint16(b[0])<<8 | uint16(b[1])
}
