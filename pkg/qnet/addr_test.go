package qnet

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetFamily_String(t *testing.T) {
	tests := []struct {
		name     string
		family   NetFamily
		expected string
	}{
		{"IPv4", NetFamily_IPv4, "ipv4"},
		{"IPv6", NetFamily_IPv6, "ipv6"},
		{"Unknown", NetFamily_Unknown, "unknown"},
		{"Custom", NetFamily("custom"), "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.family.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNetAddr_Network(t *testing.T) {
	tests := []struct {
		name     string
		addr     NetAddr
		expected string
	}{
		{
			name: "IPv4 address",
			addr: NetAddr{
				Family: NetFamily_IPv4,
				IP:     net.ParseIP("192.168.1.1"),
				Port:   8080,
			},
			expected: "ipv4",
		},
		{
			name: "IPv6 address",
			addr: NetAddr{
				Family: NetFamily_IPv6,
				IP:     net.ParseIP("2001:db8::1"),
				Port:   8080,
			},
			expected: "ipv6",
		},
		{
			name: "Unknown family",
			addr: NetAddr{
				Family: NetFamily_Unknown,
				IP:     net.ParseIP("192.168.1.1"),
				Port:   8080,
			},
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.addr.Network()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNetAddr_String(t *testing.T) {
	tests := []struct {
		name     string
		addr     NetAddr
		expected string
	}{
		{
			name: "IPv4 address",
			addr: NetAddr{
				Family: NetFamily_IPv4,
				IP:     net.ParseIP("192.168.1.1"),
				Port:   8080,
			},
			expected: "192.168.1.1:8080",
		},
		{
			name: "IPv6 address",
			addr: NetAddr{
				Family: NetFamily_IPv6,
				IP:     net.ParseIP("2001:db8::1"),
				Port:   8080,
			},
			expected: "[2001:db8::1]:8080",
		},
		{
			name: "Unknown family",
			addr: NetAddr{
				Family: NetFamily_Unknown,
				IP:     net.ParseIP("192.168.1.1"),
				Port:   8080,
			},
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.addr.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNetAddrFromTCPAddr(t *testing.T) {
	tests := []struct {
		name           string
		tcpAddr        *net.TCPAddr
		expectedFamily NetFamily
		expectedPort   uint16
	}{
		{
			name:           "IPv4 TCP address",
			tcpAddr:        &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			expectedFamily: NetFamily_IPv4,
			expectedPort:   8080,
		},
		{
			name:           "IPv6 TCP address",
			tcpAddr:        &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 9090},
			expectedFamily: NetFamily_IPv6,
			expectedPort:   9090,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NetAddrFromTCPAddr(tt.tcpAddr)
			assert.Equal(t, tt.expectedFamily, result.Family)
			assert.Equal(t, tt.expectedPort, result.Port)
			assert.True(t, tt.tcpAddr.IP.Equal(result.IP))
		})
	}
}

func TestNetAddr_Equal(t *testing.T) {
	addr1 := NetAddr{
		Family: NetFamily_IPv4,
		IP:     net.ParseIP("192.168.1.1"),
		Port:   8080,
	}

	addr2 := NetAddr{
		Family: NetFamily_IPv4,
		IP:     net.ParseIP("192.168.1.1"),
		Port:   8080,
	}

	addr3 := NetAddr{
		Family: NetFamily_IPv4,
		IP:     net.ParseIP("192.168.1.2"),
		Port:   8080,
	}

	addr4 := NetAddr{
		Family: NetFamily_IPv4,
		IP:     net.ParseIP("192.168.1.1"),
		Port:   9090,
	}

	addr5 := NetAddr{
		Family: NetFamily_IPv6,
		IP:     net.ParseIP("2001:db8::1"),
		Port:   8080,
	}

	assert.True(t, addr1.Equal(addr2), "identical addresses should be equal")
	assert.False(t, addr1.Equal(addr3), "addresses with different IPs should not be equal")
	assert.False(t, addr1.Equal(addr4), "addresses with different ports should not be equal")
	assert.False(t, addr1.Equal(addr5), "addresses with different families should not be equal")
}

func TestNetAddr_Empty(t *testing.T) {
	emptyAddr := NetAddr{}

	nonEmptyAddrs := []NetAddr{
		{
			Family: NetFamily_IPv4,
			IP:     net.ParseIP("192.168.1.1"),
			Port:   8080,
		},
		{
			Family: NetFamily_Unknown,
			IP:     nil,
			Port:   8080,
		},
		{
			Family: NetFamily_IPv4,
			IP:     net.ParseIP("0.0.0.0"),
			Port:   0,
		},
	}

	assert.True(t, emptyAddr.Empty(), "empty address should return true for Empty()")

	for i, addr := range nonEmptyAddrs {
		assert.False(t, addr.Empty(), "non-empty address #%d should return false for Empty()", i)
	}
}

func TestNetAddr_ControlValues(t *testing.T) {
	addr := NetAddr{
		Family: NetFamily_IPv4,
		IP:     net.ParseIP("192.168.1.1"),
		Port:   8080,
	}

	expected := map[string]any{
		"ip":   addr.IP,
		"port": int(addr.Port),
	}

	result := addr.ControlValues()
	require.Equal(t, expected, result)

	// Check the returned map values
	assert.Equal(t, addr.IP, result["ip"])
	assert.Equal(t, int(addr.Port), result["port"])
}

func TestNetAddr_ToBytes(t *testing.T) {
	tests := []struct {
		name     string
		addr     NetAddr
		expected [16]byte
	}{
		{
			name: "IPv4 address",
			addr: NetAddr{
				Family: NetFamily_IPv4,
				IP:     net.ParseIP("192.168.1.1"),
				Port:   8080,
			},
			expected: [16]byte{192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name: "IPv6 address",
			addr: NetAddr{
				Family: NetFamily_IPv6,
				IP:     net.ParseIP("2001:db8::1"),
				Port:   8080,
			},
			expected: [16]byte{32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		},
		{
			name: "Unknown family",
			addr: NetAddr{
				Family: NetFamily_Unknown,
				IP:     net.ParseIP("192.168.1.1"),
				Port:   8080,
			},
			expected: [16]byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.addr.ToBytes()
			assert.Equal(t, tt.expected, result)
		})
	}
}
