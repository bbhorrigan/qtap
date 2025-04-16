package telemetry

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Gauge registers a gauge and returns a set function
func (f *factory) Gauge(name string, opts ...Option) GaugeFn {
	options := &CommonOptions{}
	for _, opt := range opts {
		opt(options)
	}

	metricOpts := prometheus.GaugeOpts{
		Name: name,
		Help: "Gauge for " + name,
	}
	if options.description != "" {
		metricOpts.Help = options.description
	}

	gauge := promauto.With(f.registerer).NewGaugeVec(metricOpts, options.labels)
	if f.registerer != defaultRegisterer {
		// this gauge is for a custom collector

		// store references to all creates gauges so we can reset them when the collector is scraped
		// otherwise, orphaned label values will continue to be exported
		f.gauges = append(f.gauges, gauge)
	}
	return func(value float64, labels ...string) {
		gauge.WithLabelValues(labels...).Set(value)
	}
}
