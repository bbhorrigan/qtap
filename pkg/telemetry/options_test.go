package telemetry

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWithDescription(t *testing.T) {
	options := &CommonOptions{}
	opt := WithDescription("Test description")

	// Apply the option
	opt(options)

	assert.Equal(t, "Test description", options.description, "Description should be set correctly")
}

func TestWithLabels(t *testing.T) {
	tests := []struct {
		name           string
		inputLabels    []string
		expectedLabels []string
	}{
		{
			name:           "Empty labels",
			inputLabels:    []string{},
			expectedLabels: []string{},
		},
		{
			name:           "Single label",
			inputLabels:    []string{"label1"},
			expectedLabels: []string{"label1"},
		},
		{
			name:           "Multiple labels",
			inputLabels:    []string{"label1", "label2", "label3"},
			expectedLabels: []string{"label1", "label2", "label3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := &CommonOptions{}
			opt := WithLabels(tt.inputLabels...)

			// Apply the option
			opt(options)

			assert.Equal(t, tt.expectedLabels, options.labels, "Labels should be set correctly")
		})
	}
}

func TestSnakeCase_Additional(t *testing.T) {
	tests := []struct {
		name     string
		segments []string
		expected string
	}{
		{
			name:     "All empty segments",
			segments: []string{"", "", ""},
			expected: "",
		},
		{
			name:     "Mix of empty and non-empty segments",
			segments: []string{"", "foo", "", "bar", ""},
			expected: "foo_bar",
		},
		{
			name:     "No segments",
			segments: []string{},
			expected: "",
		},
		{
			name:     "Non-empty segments",
			segments: []string{"test", "snake", "case"},
			expected: "test_snake_case",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SnakeCase(tt.segments...)
			assert.Equal(t, tt.expected, result, "SnakeCase should correctly join segments with underscores, excluding empty segments")
		})
	}
}
