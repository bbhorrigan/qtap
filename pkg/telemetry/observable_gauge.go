package telemetry

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ObservableGauge registers a gauge that uses a callback function to compute its value
func (f *factory) ObservableGauge(name string, fn func() float64, opts ...Option) {
	options := CommonOptions{}
	for _, opt := range opts {
		opt(&options)
	}
	if len(options.labels) > 0 {
		panic("ObservableGauge does not support labels")
	}

	metricOpts := prometheus.GaugeOpts{
		Name: name,
		Help: "Observable gauge for " + name,
	}
	if options.description != "" {
		metricOpts.Help = options.description
	}

	promauto.With(f.registerer).NewGaugeFunc(metricOpts, fn)
}
