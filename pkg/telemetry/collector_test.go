package telemetry

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

func TestCollector(t *testing.T) {
	registry := prometheus.NewRegistry()
	c := &testCollector{}
	registerCollector(c, registry)

	// first scrape
	wantOutput := `
		# HELP test_counter_total test counter
		# TYPE test_counter_total counter
		test_counter_total 100
		# HELP test_gauge test gauge
		# TYPE test_gauge gauge
		test_gauge{label1="one",label2="two"} 200
		test_gauge{label1="uno",label2="dos"} 300
		# HELP test_observable_gauge test observable gauge
		# TYPE test_observable_gauge gauge
		test_observable_gauge 42
	`
	err := testutil.CollectAndCompare(
		registry, strings.NewReader(wantOutput),
		"test_counter_total",
		"test_gauge",
		"test_observable_gauge",
	)
	require.NoError(t, err)

	// second scrape
	// the counter should increase
	// disable second set of labels (uno, dos) on test_gauge. it should not be exported anymore.
	c.disableSecondSetOfLabels = true

	wantOutput = `
		# HELP test_counter_total test counter
		# TYPE test_counter_total counter
		test_counter_total 200
		# HELP test_gauge test gauge
		# TYPE test_gauge gauge
		test_gauge{label1="one",label2="two"} 200
		# HELP test_observable_gauge test observable gauge
		# TYPE test_observable_gauge gauge
		test_observable_gauge 42
	`
	err = testutil.CollectAndCompare(
		registry, strings.NewReader(wantOutput),
		"test_counter_total",
		"test_gauge",
		"test_observable_gauge",
	)
	require.NoError(t, err)
}

type testCollector struct {
	testCounter CounterFn
	testGauge   GaugeFn

	disableSecondSetOfLabels bool
}

func (c *testCollector) Register(f Factory) {
	c.testCounter = f.Counter(
		"test_counter",
		WithDescription("test counter"),
	)
	c.testGauge = f.Gauge(
		"test_gauge",
		WithDescription("test gauge"),
		WithLabels("label1", "label2"),
	)

	f.ObservableGauge(
		"test_observable_gauge",
		func() float64 {
			return 42
		},
		WithDescription("test observable gauge"),
	)
}

func (c *testCollector) Collect() {
	c.testCounter(100)
	c.testGauge(200, "one", "two")
	if !c.disableSecondSetOfLabels {
		c.testGauge(300, "uno", "dos")
	}
}
