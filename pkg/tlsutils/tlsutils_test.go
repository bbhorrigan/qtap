package tlsutils

import (
	"reflect"
	"testing"
)

func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		name     string
		version  TLSVersion
		expected string
	}{
		{"TLS 1.0", VersionTLS10, "TLS 1.0"},
		{"TLS 1.1", VersionTLS11, "TLS 1.1"},
		{"TLS 1.2", VersionTLS12, "TLS 1.2"},
		{"TLS 1.3", VersionTLS13, "TLS 1.3"},
		{"Unknown", TLSVersion(0x0305), "0x0305"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.version.String(); got != tt.expected {
				t.Errorf("TLSVersion.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestTLSVersionFloat(t *testing.T) {
	tests := []struct {
		name     string
		version  TLSVersion
		expected float64
	}{
		{"TLS 1.0", VersionTLS10, 1.0},
		{"TLS 1.1", VersionTLS11, 1.1},
		{"TLS 1.2", VersionTLS12, 1.2},
		{"TLS 1.3", VersionTLS13, 1.3},
		{"Unknown", TLSVersion(0x0305), 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.version.Float(); got != tt.expected {
				t.Errorf("TLSVersion.Float() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestClientHelloControlValues(t *testing.T) {
	tests := []struct {
		name     string
		hello    *ClientHello
		expected map[string]any
	}{
		{
			"Complete ClientHello",
			&ClientHello{
				SNI:     "example.com",
				Version: VersionTLS13,
				ALPNs:   []string{"h2", "http/1.1"},
			},
			map[string]any{
				"enabled": true,
				"version": 1.3,
				"sni":     "example.com",
				"alpn":    []string{"h2", "http/1.1"},
			},
		},
		{
			"Empty ClientHello",
			&ClientHello{},
			map[string]any{
				"enabled": true,
				"version": 0.0,
				"sni":     "",
				"alpn":    []string(nil),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.hello.ControlValues(); !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("ClientHello.ControlValues() = %v, want %v", got, tt.expected)
			}
		})
	}
}
