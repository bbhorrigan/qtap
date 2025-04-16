package process

import "github.com/qpoint-io/qtap/pkg/telemetry"

var (
	// processAddTotal tracks the number of processes added
	processAddTotal = telemetry.Counter("processes_added",
		telemetry.WithDescription("Total number of processes added"))

	// processRemoveTotal tracks the number of processes removed
	processRemoveTotal = telemetry.Counter("processes_removed",
		telemetry.WithDescription("Total number of processes removed"))

	// processRenamedTotal tracks the number of processes renamed
	processRenamedTotal = telemetry.Counter("processes_renamed",
		telemetry.WithDescription("Total number of processes renamed"))
)

// trackActiveProcessCount tracks the number of active processes as an observable gauge
func trackActiveProcessCount(fn func() int) {
	telemetry.ObservableGauge("processes_active",
		func() float64 {
			return float64(fn())
		},
		telemetry.WithDescription("Total number of active monitored processes"),
	)
}

// IncrementProcessAdd increments the process add counter
func incrementProcessAdd() {
	processAddTotal(1)
}

// IncrementProcessRemove increments the process remove counter
func incrementProcessRemove() {
	processRemoveTotal(1)
}

// IncrementProcessRenamed increments the process renamed counter
func incrementProcessRenamed() {
	processRenamedTotal(1)
}
