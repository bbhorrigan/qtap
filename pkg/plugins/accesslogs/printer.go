package accesslogs

import (
	"github.com/qpoint-io/qtap/pkg/plugins"
	"go.uber.org/zap"
)

// Printer defines the interface for different access log formatting implementations
type Printer interface {
	// PrintSummary prints a brief summary of the HTTP transaction
	PrintSummary()

	// PrintDetails prints detailed information about the HTTP transaction
	PrintDetails() error

	// PrintFull prints detailed information including request and response bodies
	PrintFull() error
}

// LoggerFactory creates a new Logger based on the specified format
func NewPrinter(
	format outputFormat,
	ctx plugins.PluginContext,
	reqheaders plugins.Headers,
	resheaders plugins.Headers,
	logger *zap.Logger,
	writer *zap.Logger,
) Printer {
	switch format {
	case outputFormatJSON:
		return NewJSONPrinter(ctx, reqheaders, resheaders, logger, writer)
	case outputFormatConsole:
		return NewConsolePrinter(ctx, reqheaders, resheaders, logger, writer)
	default:
		return NewJSONPrinter(ctx, reqheaders, resheaders, logger, writer)
	}
}
