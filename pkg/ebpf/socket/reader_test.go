package socket

import (
	"encoding/binary"
	"testing"
)

func Test_fixPortEndianness(t *testing.T) {
	tests := []struct {
		name         string
		inputPort    uint16
		systemEndian binary.ByteOrder
		expectedPort uint16
	}{
		{
			name:         "big endian system - port 80",
			inputPort:    0x0050, // 80 in big endian
			systemEndian: binary.BigEndian,
			expectedPort: 80,
		},
		{
			name:         "big endian system - port 443",
			inputPort:    0x01BB, // 443 in big endian
			systemEndian: binary.BigEndian,
			expectedPort: 443,
		},
		{
			name:         "little endian system - port 80",
			inputPort:    0x5000, // 80 in big endian read as little endian
			systemEndian: binary.LittleEndian,
			expectedPort: 80,
		},
		{
			name:         "little endian system - port 443",
			inputPort:    0xBB01, // 443 in big endian read as little endian
			systemEndian: binary.LittleEndian,
			expectedPort: 443,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fixPortEndianness(tt.systemEndian, tt.inputPort)
			if got != tt.expectedPort {
				t.Errorf("fixPortEndianness() = %d, want %d", got, tt.expectedPort)
			}
		})
	}
}
