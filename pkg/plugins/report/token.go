package report

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

type TokenType string

const (
	TypeUnknown   TokenType = "unknown"
	TypeJWT       TokenType = "jwt"
	TypeAPIKey    TokenType = "api_key"
	TypeBasicAuth TokenType = "basic_auth"
	TypeBearer    TokenType = "bearer_token"
	TypeOAuth     TokenType = "oauth_token"
)

func detectTokenType(source, value string) TokenType {
	lowerSource := strings.ToLower(source)
	lowerValue := strings.ToLower(value)

	if isJWT(value) {
		return TypeJWT
	}

	if strings.HasPrefix(lowerValue, "basic ") {
		return TypeBasicAuth
	}

	if strings.HasPrefix(lowerValue, "bearer ") {
		return TypeBearer
	}

	if strings.Contains(lowerSource, "oauth") || strings.Contains(lowerValue, "oauth") {
		return TypeOAuth
	}

	if strings.Contains(lowerSource, "api") || strings.Contains(lowerSource, "key") {
		return TypeAPIKey
	}

	// If no specific type is detected, return unknown
	return TypeUnknown
}

func isJWT(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}

	// Attempt to decode the payload
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	// Check if the payload is valid JSON
	var js json.RawMessage
	return json.Unmarshal(payload, &js) == nil
}

func maskToken(token string, tokenType TokenType) string {
	if len(token) == 0 {
		return ""
	}

	var maskedToken string

	switch tokenType {
	case TypeBasicAuth, TypeBearer, TypeOAuth:
		parts := strings.SplitN(token, " ", 2)
		if len(parts) == 2 {
			maskedToken = maskActualToken(parts[1])
		} else {
			maskedToken = maskActualToken(token)
		}
	default:
		maskedToken = maskActualToken(token)
	}

	return maskedToken
}

// maskActualToken masks a given token string based on its length:
//   - For tokens with 8 or fewer characters: All characters are masked with asterisks.
//   - For tokens with 9 to 16 characters: The first two and last two characters are shown,
//     with the rest masked by asterisks.
//   - For tokens with more than 16 characters: The first four and last four characters are shown,
//     with the middle portion represented as "***(n)***", where n is the number of masked characters.
//
// This function ensures that sensitive information is partially hidden while still providing
// some visibility of the token's structure.
//
// Parameters:
//   - token: The string to be masked.
//
// Returns:
//   - A string with the appropriate masking applied.
func maskActualToken(token string) string {
	switch {
	case len(token) <= 8:
		return strings.Repeat("*", len(token))
	case len(token) <= 16:
		return token[:2] + strings.Repeat("*", len(token)-4) + token[len(token)-2:]
	default:
		maskedLength := len(token) - 8
		return fmt.Sprintf("%s***(%d)***%s", token[:4], maskedLength, token[len(token)-4:])
	}
}

// hashToken takes a string token and returns its SHA-256 hash as a hexadecimal string.
func hashToken(token string) string {
	// Create a new SHA-256 hash
	hasher := sha256.New()

	// Write the token to the hasher
	hasher.Write([]byte(token))

	// Get the final hash and convert it to a hexadecimal string
	hashBytes := hasher.Sum(nil)
	hashString := hex.EncodeToString(hashBytes)

	return hashString
}
