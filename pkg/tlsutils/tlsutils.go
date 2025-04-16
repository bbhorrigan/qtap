// TODO: This package has high cyclomatic complexity.
//
//nolint:cyclop
package tlsutils

import (
	"crypto/tls"

	"golang.org/x/crypto/cryptobyte"
)

type ClientHello struct {
	SNI     string
	Version TLSVersion
	ALPNs   []string
}

type TLSVersion uint16

// TLS version constants
const (
	VersionTLS10 TLSVersion = 0x0301
	VersionTLS11 TLSVersion = 0x0302
	VersionTLS12 TLSVersion = 0x0303
	VersionTLS13 TLSVersion = 0x0304
)

func (v TLSVersion) String() string {
	return tls.VersionName(uint16(v))
}

func (v TLSVersion) Float() float64 {
	switch v {
	case VersionTLS10:
		return 1.0
	case VersionTLS11:
		return 1.1
	case VersionTLS12:
		return 1.2
	case VersionTLS13:
		return 1.3
	default:
		return 0
	}
}

// ParseClientHello parses a TLS client hello message from a byte slice.
func ParseClientHello(record []byte) (c *ClientHello, ok bool) {
	c = &ClientHello{}

	in := cryptobyte.String(record)
	if !in.Skip(1) || !in.Skip(2) {
		return nil, false
	}
	var msg cryptobyte.String
	if !in.ReadUint16LengthPrefixed(&msg) || !in.Empty() {
		return nil, false
	}

	var msgType uint8
	if !msg.ReadUint8(&msgType) {
		return nil, false
	}

	var ch cryptobyte.String
	if !msg.ReadUint24LengthPrefixed(&ch) || !msg.Empty() {
		return nil, false
	}

	var legacyVersion uint16
	if !ch.ReadUint16(&legacyVersion) {
		return nil, false
	}
	c.Version = TLSVersion(legacyVersion)

	if !ch.Skip(32) {
		return nil, false
	}

	var skip cryptobyte.String
	if !ch.ReadUint8LengthPrefixed(&skip) ||
		!ch.ReadUint16LengthPrefixed(&skip) ||
		!ch.ReadUint8LengthPrefixed(&skip) {
		return nil, false
	}
	var exts cryptobyte.String
	if !ch.ReadUint16LengthPrefixed(&exts) || !ch.Empty() {
		return nil, false
	}

	for !exts.Empty() {
		var extensionType uint16
		if !exts.ReadUint16(&extensionType) {
			return nil, false
		}

		var ex cryptobyte.String
		if !exts.ReadUint16LengthPrefixed(&ex) {
			return nil, false
		}

		switch extensionType {
		case 0:
			var snl cryptobyte.String
			if !ex.ReadUint16LengthPrefixed(&snl) || !ex.Empty() {
				return nil, false
			}

			for !snl.Empty() {
				var nameType uint8
				if !snl.ReadUint8(&nameType) {
					return nil, false
				}
				var hostName cryptobyte.String
				if !snl.ReadUint16LengthPrefixed(&hostName) {
					return nil, false
				}

				if nameType != 0 {
					return nil, false
				}
				c.SNI = string(hostName)
			}

		case 16:
			var protocolNameList cryptobyte.String
			if !ex.ReadUint16LengthPrefixed(&protocolNameList) || !ex.Empty() {
				return nil, false
			}

			var protocols []string
			for !protocolNameList.Empty() {
				var protocol cryptobyte.String
				if !protocolNameList.ReadUint8LengthPrefixed(&protocol) {
					return nil, false
				}
				protocols = append(protocols, string(protocol))
			}
			c.ALPNs = protocols

		case 43:
			var versions cryptobyte.String
			if !ex.ReadUint8LengthPrefixed(&versions) || !ex.Empty() {
				return nil, false
			}

			var highestVersion uint16
			for !versions.Empty() {
				var version uint16
				if !versions.ReadUint16(&version) {
					return nil, false
				}
				if version > highestVersion {
					highestVersion = version
				}
			}
			if highestVersion != 0 {
				c.Version = TLSVersion(highestVersion)
			}
		default:
			// For any other extension type, we simply continue to the next extension
			// The extension data has already been read into 'ex' and will be automatically
			// skipped when we continue the loop
			continue
		}
	}

	return c, true
}

func (c *ClientHello) ControlValues() map[string]any {
	return map[string]any{
		"enabled": true,
		"version": c.Version.Float(),
		"sni":     c.SNI,
		"alpn":    c.ALPNs,
	}
}
