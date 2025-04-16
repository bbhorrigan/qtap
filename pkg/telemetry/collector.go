package telemetry

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Collector provides a way to batch collect metrics.
//
// Register() is called upon creation to register the metrics. All metrics must be registered
// on the provided Factory. The global functions such as telemetry.Counter() may not be used.
//
// On collection, it will signal Collect(). The collector must compute the latest values
// synchronously and set them on its metrics.
type Collector interface {
	Register(Factory)
	Collect()
}

// RegisterCollector registers a collector.
func RegisterCollector(c Collector) {
	registerCollector(c, defaultRegisterer)
}

func registerCollector(c Collector, registerer prometheus.Registerer) {
	// create a registry and have the collector register its metrics on it
	registry := prometheus.NewRegistry()
	factory := &factory{
		registerer: registry,
	}
	collector := &collector{
		collector: c,
		registry:  registry,
		factory:   factory,
	}

	// register the metrics
	c.Register(factory)
	// register the collector with the actual prometheus registry
	registerer.MustRegister(collector)
}

// collector bridges between Collector and prometheus.Collector.
type collector struct {
	collector Collector
	registry  *prometheus.Registry
	factory   *factory
}

// Describe implements prometheus.Collector.
func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	c.registry.Describe(ch)
}

// Collect implements prometheus.Collector.
func (c *collector) Collect(ch chan<- prometheus.Metric) {
	// reset all gauges to avoid orphaned label values
	for _, gauge := range c.factory.gauges {
		gauge.Reset()
	}

	// signal that we are collecting metrics so that the collector can compute the latest values
	c.collector.Collect()

	// collect the metrics from the registry
	c.registry.Collect(ch)
}
