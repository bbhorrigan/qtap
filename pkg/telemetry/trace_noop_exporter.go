package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/sdk/trace"
)

// NoopSpanExporter is an implementation of trace.SpanExporter that performs no operations.
type NoopSpanExporter struct{}

var _ trace.SpanExporter = NoopSpanExporter{}

// ExportSpans is part of trace.SpanExporter interface.
func (e NoopSpanExporter) ExportSpans(ctx context.Context, spans []trace.ReadOnlySpan) error {
	return nil
}

// Shutdown is part of trace.SpanExporter interface.
func (e NoopSpanExporter) Shutdown(ctx context.Context) error {
	return nil
}
