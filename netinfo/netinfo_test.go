//go:build windows

package netinfo

import (
	"encoding/binary"
	"testing"
)

func TestPortFromBytes(t *testing.T) {
	// Port 4444 (0x115C) is stored big-endian in the low two bytes.
	b := []byte{0x11, 0x5C, 0x00, 0x00}
	if got := portFromBytes(b); got != 4444 {
		t.Errorf("portFromBytes(%v) = %d, want 4444", b, got)
	}
}

func TestIPFromBytes(t *testing.T) {
	b := []byte{203, 0, 113, 77}
	if got := ipFromBytes(b); got != "203.0.113.77" {
		t.Errorf("ipFromBytes(%v) = %q, want 203.0.113.77", b, got)
	}
}

// TestParseTCPTable hand-builds a MIB_TCPTABLE_OWNER_PID buffer with two
// rows and checks both are decoded correctly — this is the parsing logic
// GetExtendedTcpTable results flow through, verified without needing a
// live connection table.
func TestParseTCPTable(t *testing.T) {
	buf := make([]byte, 4+2*tcpRowSize)
	binary.LittleEndian.PutUint32(buf[0:4], 2)

	// Row 0: state, localAddr, localPort ignored by our parser; remoteAddr
	// 203.0.113.77, remotePort 4444, owning PID 1234.
	row0 := buf[4 : 4+tcpRowSize]
	copy(row0[12:16], []byte{203, 0, 113, 77})
	copy(row0[16:20], []byte{0x11, 0x5C, 0, 0})
	binary.LittleEndian.PutUint32(row0[20:24], 1234)

	// Row 1: listening socket, remote 0.0.0.0:0, PID 999.
	row1 := buf[4+tcpRowSize : 4+2*tcpRowSize]
	binary.LittleEndian.PutUint32(row1[20:24], 999)

	got := parseTCPTable(buf)
	if len(got) != 2 {
		t.Fatalf("parseTCPTable returned %d endpoints, want 2", len(got))
	}

	if got[0].IP != "203.0.113.77" || got[0].Port != 4444 || got[0].PID != 1234 {
		t.Errorf("row 0 = %+v, want {IP:203.0.113.77 Port:4444 PID:1234}", got[0])
	}
	if got[1].IP != "0.0.0.0" || got[1].PID != 999 {
		t.Errorf("row 1 = %+v, want {IP:0.0.0.0 PID:999}", got[1])
	}
}

func TestLiveEndpointsFiltersByPIDAndDropsListeners(t *testing.T) {
	orig := Source
	defer func() { Source = orig }()

	Source = fakeTCPTable{endpoints: []Endpoint{
		{PID: 1234, IP: "203.0.113.77", Port: 4444},
		{PID: 1234, IP: "0.0.0.0", Port: 0}, // listening, should be dropped
		{PID: 999, IP: "8.8.8.8", Port: 53}, // not in our PID set
	}}

	got, err := LiveEndpoints(map[uint32]bool{1234: true})
	if err != nil {
		t.Fatalf("LiveEndpoints error: %v", err)
	}
	if len(got) != 1 || got[0].IP != "203.0.113.77" {
		t.Fatalf("LiveEndpoints = %+v, want just the 203.0.113.77 endpoint for PID 1234", got)
	}
}

type fakeTCPTable struct{ endpoints []Endpoint }

func (f fakeTCPTable) Read() ([]Endpoint, error) { return f.endpoints, nil }

func TestIsNoise(t *testing.T) {
	cases := map[string]bool{
		"0.0.0.0":      true,
		"127.0.0.1":    true,
		"127.1.2.3":    true,
		"203.0.113.77": false,
		"192.168.1.1":  false,
	}
	for ip, want := range cases {
		if got := isNoise(ip); got != want {
			t.Errorf("isNoise(%q) = %v, want %v", ip, got, want)
		}
	}
}
