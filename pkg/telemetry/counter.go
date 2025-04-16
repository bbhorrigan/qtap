package telemetry

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Counter registers a counter and returns an increment function
func (f *factory) Counter(name string, opts ...Option) CounterFn {
	options := &CommonOptions{}
	for _, opt := range opts {
		opt(options)
	}

	metricOpts := prometheus.CounterOpts{
		Name: name + "_total",
		Help: "Counter for " + name,
	}
	if options.description != "" {
		metricOpts.Help = options.description
	}

	counter := promauto.With(f.registerer).NewCounterVec(metricOpts, options.labels)
	return func(value float64, labels ...string) {
		counter.WithLabelValues(labels...).Add(value)
	}
}
