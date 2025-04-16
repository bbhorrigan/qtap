package tools

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTokenizePath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected []string
	}{
		{"Normal path", "/path/to/resource", []string{"path", "to", "resource"}},
		{"Trailing slash", "/path/to/resource/", []string{"path", "to", "resource"}},
		{"Leading and trailing slash", "/path/to/resource/", []string{"path", "to", "resource"}},
		{"Multiple slashes", "//path//to//resource//", []string{"path", "to", "resource"}},
		{"Empty path", "", []string{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tokenizePath(tc.path)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestIsLikelyWord(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"Valid short word", "word", true},
		{"Too short", "w", false},
		{"Too long", "thisiswaytoolongforaword", false},
		{"Contains numbers", "word123", false},
		{"Contains special characters", "word-word", false},
		{"Empty string", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isLikelyWord(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestNormalizeSegments(t *testing.T) {
	tests := []struct {
		name     string
		segments []string
		expected []string
	}{
		{"Single word", []string{"article"}, []string{"article"}},
		{"Valid words", []string{"user", "name"}, []string{"user", "name"}},
		{"Contains id", []string{"user", "123"}, []string{"user", "{userId}"}},
		{"Multiple ids", []string{"user", "123", "page", "456"}, []string{"user", "{userId}", "page", "{pageId}"}},
		{"Mixed valid and invalid", []string{"user", "", "page", "123"}, []string{"user", "page", "{pageId}"}},
		{"Placeholder transformation", []string{"user", "{userId}", "page", "123"}, []string{"user", "{userId}", "page", "{pageId}"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := normalizeSegments(tc.segments)
			assert.Equal(t, tc.expected, result)
		})
	}
}
