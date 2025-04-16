package tools

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMimeCategory(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		expected    string
	}{
		{"Empty content type", "", "other"},
		{"Content type with params", "application/json; charset=utf-8", "app"},

		// App type tests
		{"HTML content", "text/html", "app"},
		{"JSON content", "application/json", "app"},
		{"GRPC content", "application/grpc", "app"},
		{"XML content (text)", "text/xml", "app"},
		{"XML content (application)", "application/xml", "app"},
		{"Plain text", "text/plain", "app"},

		// CSS type tests
		{"CSS content", "text/css", "css"},

		// JavaScript type tests
		{"JavaScript content", "text/javascript", "js"},

		// Font type tests
		{"Font content", "font/woff2", "font"},
		{"Font content with prefix", "font-awesome/woff", "font"},

		// Image type tests
		{"PNG image", "image/png", "image"},
		{"JPEG image", "image/jpeg", "image"},
		{"SVG image", "image/svg+xml", "image"},

		// Media type tests
		{"Audio content", "audio/mp3", "media"},
		{"Video content", "video/mp4", "media"},

		// Other type tests
		{"PDF content", "application/pdf", "other"},
		{"Zip content", "application/zip", "other"},
		{"Unknown content", "unknown/type", "other"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MimeCategory(tt.contentType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsApp(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		expected    bool
	}{
		{"HTML content", "text/html", true},
		{"JSON content", "application/json", true},
		{"GRPC content", "application/grpc", true},
		{"XML content (text)", "text/xml", true},
		{"XML content (application)", "application/xml", true},
		{"Plain text", "text/plain", true},
		{"CSS content", "text/css", false},
		{"JavaScript content", "text/javascript", false},
		{"Image content", "image/png", false},
		{"Unknown content", "unknown/type", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isApp(tt.contentType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsTypes(t *testing.T) {
	// Testing isCss function
	assert.True(t, isCss("text/css"))
	assert.False(t, isCss("text/javascript"))

	// Testing isJs function
	assert.True(t, isJs("text/javascript"))
	assert.False(t, isJs("text/css"))

	// Testing isFont function
	assert.True(t, isFont("font/woff"))
	assert.True(t, isFont("font-awesome/otf"))
	assert.False(t, isFont("text/css"))

	// Testing isImage function
	assert.True(t, isImage("image/png"))
	assert.True(t, isImage("image/jpeg"))
	assert.False(t, isImage("text/css"))

	// Testing isMedia function
	assert.True(t, isMedia("audio/mp3"))
	assert.True(t, isMedia("video/mp4"))
	assert.False(t, isMedia("text/css"))
}
