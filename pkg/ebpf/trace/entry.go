package trace

import "go.uber.org/zap"

type TraceEntry struct {
	msg    string
	fields []zap.Field
}

func NewTraceEntry(msg string) *TraceEntry {
	return &TraceEntry{msg: msg}
}

func (e *TraceEntry) AddField(field zap.Field) {
	e.fields = append(e.fields, field)
}

func (e *TraceEntry) Print(logger *zap.Logger) {
	// construct the fields
	fields := append([]zap.Field{zap.String("msg", e.msg)}, e.fields...)

	// generate the log entry
	logger.Info("eBPF trace", fields...)
}
