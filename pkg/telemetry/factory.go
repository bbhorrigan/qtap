package telemetry

import "github.com/prometheus/client_golang/prometheus"

var defaultRegisterer = prometheus.DefaultRegisterer

// Factory produces metrics.
type Factory interface {
	Counter(name string, opts ...Option) CounterFn
	Gauge(name string, opts ...Option) GaugeFn
	ObservableGauge(name string, fn func() float64, opts ...Option)
}

type factory struct {
	registerer prometheus.Registerer
	gauges     []*prometheus.GaugeVec
}

func Counter(name string, opts ...Option) CounterFn {
	return (&factory{
		registerer: defaultRegisterer,
	}).Counter(name, opts...)
}

func Gauge(name string, opts ...Option) GaugeFn {
	return (&factory{
		registerer: defaultRegisterer,
	}).Gauge(name, opts...)
}

func ObservableGauge(name string, fn func() float64, opts ...Option) {
	(&factory{
		registerer: defaultRegisterer,
	}).ObservableGauge(name, fn, opts...)
}
