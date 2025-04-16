package report

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetectTokenType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		source   string
		value    string
		expected TokenType
	}{
		{
			name:     "JWT Token",
			source:   "Authorization",
			value:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			expected: TypeJWT,
		},
		{
			name:     "Basic Auth",
			source:   "Authorization",
			value:    "Basic dXNlcm5hbWU6cGFzc3dvcmQ=",
			expected: TypeBasicAuth,
		},
		{
			name:     "Bearer Token",
			source:   "Authorization",
			value:    "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
			expected: TypeBearer,
		},
		{
			name:     "OAuth Token in source",
			source:   "X-OAuth-Token",
			value:    "1234567890abcdef",
			expected: TypeOAuth,
		},
		{
			name:     "OAuth Token in value",
			source:   "Authorization",
			value:    "OAuth 1234567890abcdef",
			expected: TypeOAuth,
		},
		{
			name:     "API Key",
			source:   "X-API-Key",
			value:    "api_1234567890abcdef",
			expected: TypeAPIKey,
		},
		{
			name:     "Unknown Token Type",
			source:   "Custom-Header",
			value:    "1234567890abcdef",
			expected: TypeUnknown, // Assuming unknown types default to API Key
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectTokenType(tt.source, tt.value)
			assert.Equal(t, tt.expected, result, "detectTokenType() returned unexpected result")
		})
	}
}

func TestIsJWT(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		token    string
		expected bool
	}{
		{
			name:     "Valid JWT",
			token:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			expected: true,
		},
		{
			name:     "Invalid JWT - Wrong number of parts",
			token:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
			expected: false,
		},
		{
			name:     "Invalid JWT - Not Base64 encoded",
			token:    "header.payload.signature",
			expected: false,
		},
		{
			name:     "Invalid JWT - Invalid JSON in payload",
			token:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aW52YWxpZCBqc29u.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			expected: false,
		},
		{
			name:     "Not a JWT - API Key",
			token:    "api_1234567890abcdef",
			expected: false,
		},
		{
			name:     "Empty string",
			token:    "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isJWT(tt.token)
			assert.Equal(t, tt.expected, result, "isJWT() returned unexpected result")
		})
	}
}

func TestMaskToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		token     string
		tokenType TokenType
		expected  string
	}{
		{
			name:      "Short API Key",
			token:     "1234567",
			tokenType: TypeAPIKey,
			expected:  "*******",
		},
		{
			name:      "Medium API Key",
			token:     "1234567890123",
			tokenType: TypeAPIKey,
			expected:  "12*********23",
		},
		{
			name:      "Long API Key",
			token:     "1234567890123456789",
			tokenType: TypeAPIKey,
			expected:  "1234***(11)***6789",
		},
		{
			name:      "Basic Auth",
			token:     "Basic dXNlcm5hbWU6cGFzc3dvcmQ=",
			tokenType: TypeBasicAuth,
			expected:  "dXNl***(16)***cmQ=",
		},
		{
			name:      "Bearer Token",
			token:     "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			tokenType: TypeBearer,
			expected:  "eyJh***(147)***sw5c",
		},
		{
			name:      "OAuth Token",
			token:     "OAuth 1234567890abcdef",
			tokenType: TypeOAuth,
			expected:  "12************ef",
		},
		{
			name:      "JWT",
			token:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			tokenType: TypeJWT,
			expected:  "eyJh***(147)***sw5c",
		},
		{
			name:      "Empty Token",
			token:     "",
			tokenType: TypeAPIKey,
			expected:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskToken(tt.token, tt.tokenType)
			assert.Equal(t, tt.expected, result, "maskToken() returned unexpected result")
		})
	}
}

func TestMaskActualToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		token    string
		expected string
	}{
		{
			name:     "Empty token",
			token:    "",
			expected: "",
		},
		{
			name:     "Short token (<=8 characters)",
			token:    "12345678",
			expected: "********",
		},
		{
			name:     "Medium token (9-16 characters)",
			token:    "1234567890123456",
			expected: "12************56",
		},
		{
			name:     "Long token (>16 characters)",
			token:    "12345678901234567890",
			expected: "1234***(12)***7890",
		},
		{
			name:     "Token with exactly 8 characters",
			token:    "abcdefgh",
			expected: "********",
		},
		{
			name:     "Token with exactly 16 characters",
			token:    "abcdefghijklmnop",
			expected: "ab************op",
		},
		{
			name:     "Token with 17 characters",
			token:    "abcdefghijklmnopq",
			expected: "abcd***(9)***nopq",
		},
		{
			name:     "Very long token",
			token:    "abcdefghijklmnopqrstuvwxyz1234567890",
			expected: "abcd***(28)***7890",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskActualToken(tt.token)
			assert.Equal(t, tt.expected, result, "maskActualToken() returned unexpected result")
		})
	}
}

func TestHashToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		token    string
		expected string
	}{
		{
			name:     "Empty string",
			token:    "",
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "Simple token",
			token:    "hello",
			expected: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		},
		{
			name:     "Complex token",
			token:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
			expected: "12683707dcb79426c9e1d0cafc6d37c2fedb075543ed1f1c9140e7f6c68e7f12",
		},
		{
			name:     "Token with special characters",
			token:    "p@ssw0rd!@#$%^&*()",
			expected: "7b1544a66d529cb2e763d9f5147befd118f786720e8aa4893cb41d6fc063c75e",
		},
		{
			name:     "Numeric token",
			token:    "12345678901234567890",
			expected: "6ed645ef0e1abea1bf1e4e935ff04f9e18d39812387f63cda3415b46240f0405",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hashToken(tt.token)
			assert.Equal(t, tt.expected, result, "hashToken() returned unexpected result")
		})
	}
}
