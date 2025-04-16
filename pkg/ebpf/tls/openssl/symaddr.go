package openssl

import "fmt"

type OpenSSLSymaddr struct {
	SSLVersionOffset int32
	SSLRbioOffset    int32
	SSLWbioOffset    int32
	SSLNumOffset     int32
}

const (
	MaxSupportedOpenSSL102Version = 'u'
	MaxSupportedOpenSSL110Version = 'l'
	MaxSupportedOpenSSL111Version = 'u'
	MaxSupportedOpenSSL30Version  = 12
	MaxSupportedOpenSSL31Version  = 4
	MaxSupportedOpenSSL32Version  = 0
)

var (
	BoringSSL_14 = OpenSSLSymaddr{
		SSLVersionOffset: 0x10,
		SSLRbioOffset:    0x18,
		SSLWbioOffset:    0x20,
		SSLNumOffset:     0x18,
	}
	OpenSSL_1_0_2a = OpenSSLSymaddr{
		SSLVersionOffset: 0x0,
		SSLRbioOffset:    0x10,
		SSLWbioOffset:    0x18,
		SSLNumOffset:     0x28,
	}
	OpenSSL_1_1_0a = OpenSSLSymaddr{
		SSLVersionOffset: 0x0,
		SSLRbioOffset:    0x10,
		SSLWbioOffset:    0x18,
		SSLNumOffset:     0x28,
	}
	OpenSSL_1_1_1a = OpenSSLSymaddr{
		SSLVersionOffset: 0x0,
		SSLRbioOffset:    0x10,
		SSLWbioOffset:    0x18,
		SSLNumOffset:     0x30,
	}
	OpenSSL_1_1_1b = OpenSSLSymaddr{
		SSLVersionOffset: 0x0,
		SSLRbioOffset:    0x10,
		SSLWbioOffset:    0x18,
		SSLNumOffset:     0x30,
	}
	OpenSSL_1_1_1d = OpenSSLSymaddr{
		SSLVersionOffset: 0x0,
		SSLRbioOffset:    0x10,
		SSLWbioOffset:    0x18,
		SSLNumOffset:     0x30,
	}
	OpenSSL_1_1_1j = OpenSSLSymaddr{
		SSLVersionOffset: 0x0,
		SSLRbioOffset:    0x10,
		SSLWbioOffset:    0x18,
		SSLNumOffset:     0x30,
	}
	OpenSSL_3_0_0 = OpenSSLSymaddr{
		SSLVersionOffset: 0x0,
		SSLRbioOffset:    0x10,
		SSLWbioOffset:    0x18,
		SSLNumOffset:     0x38,
	}
	OpenSSL_3_2_0 = OpenSSLSymaddr{
		SSLVersionOffset: 0x0,
		SSLRbioOffset:    0x48,
		SSLWbioOffset:    0x50,
		SSLNumOffset:     0x38,
	}

	OpenSSLSymaddrMap = map[string]OpenSSLSymaddr{}
)

func init() {
	// boring ssl
	OpenSSLSymaddrMap["openssl 1.1.1"] = BoringSSL_14
	OpenSSLSymaddrMap["boringssl 1.1.1"] = BoringSSL_14

	// group a : 1.1.1a
	OpenSSLSymaddrMap["openssl 1.1.1a"] = OpenSSL_1_1_1a

	// group b : 1.1.1b-1.1.1c
	OpenSSLSymaddrMap["openssl 1.1.1b"] = OpenSSL_1_1_1b
	OpenSSLSymaddrMap["openssl 1.1.1c"] = OpenSSL_1_1_1b

	// group c : 1.1.1d-1.1.1i
	for ch := 'd'; ch <= 'i'; ch++ {
		OpenSSLSymaddrMap["openssl 1.1.1"+string(ch)] = OpenSSL_1_1_1d
	}

	// group e : 1.1.1j-1.1.1s
	for ch := 'j'; ch <= MaxSupportedOpenSSL111Version; ch++ {
		OpenSSLSymaddrMap["openssl 1.1.1"+string(ch)] = OpenSSL_1_1_1j
	}

	// openssl 3.0.0 - 3.0.12
	for ch := 0; ch <= MaxSupportedOpenSSL30Version; ch++ {
		OpenSSLSymaddrMap[fmt.Sprintf("openssl 3.0.%d", ch)] = OpenSSL_3_0_0
	}

	// openssl 3.1.0 - 3.1.4
	for ch := 0; ch <= MaxSupportedOpenSSL31Version; ch++ {
		OpenSSLSymaddrMap[fmt.Sprintf("openssl 3.1.%d", ch)] = OpenSSL_3_0_0
	}

	// openssl 3.2.0
	for ch := 0; ch <= MaxSupportedOpenSSL32Version; ch++ {
		OpenSSLSymaddrMap[fmt.Sprintf("openssl 3.2.%d", ch)] = OpenSSL_3_2_0
	}

	// openssl 1.1.0a - 1.1.0l
	for ch := 'a'; ch <= MaxSupportedOpenSSL110Version; ch++ {
		OpenSSLSymaddrMap["openssl 1.1.0"+string(ch)] = OpenSSL_1_1_0a
	}

	// openssl 1.0.2a - 1.0.2u
	for ch := 'a'; ch <= MaxSupportedOpenSSL102Version; ch++ {
		OpenSSLSymaddrMap["openssl 1.0.2"+string(ch)] = OpenSSL_1_0_2a
	}
}
