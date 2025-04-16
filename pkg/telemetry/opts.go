package telemetry

import (
	"slices"
	"strings"
)

// CounterFn is a function type that increments a counter, accepting optional labels
type CounterFn func(float64, ...string)

// GaugeFn is a function type that sets a value, accepting optional labels
type GaugeFn func(float64, ...string)

// CommonOptions holds the common options for both counters and gauges
type CommonOptions struct {
	description string
	labels      []string
}

// Option is a function type that modifies CommonOptions
type Option func(*CommonOptions)

// WithDescription sets the description for the metric
func WithDescription(description string) Option {
	return func(o *CommonOptions) {
		o.description = description
	}
}

// WithLabels sets the labels for the metric
func WithLabels(labels ...string) Option {
	return func(o *CommonOptions) {
		o.labels = labels
	}
}

// SnakeCase joins non empty string segments with underscores
func SnakeCase(segments ...string) string {
	segments = slices.DeleteFunc(segments, func(s string) bool {
		return s == ""
	})
	return strings.Join(segments, "_")
}
