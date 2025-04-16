package tls

import (
	"errors"
	"fmt"

	"github.com/qpoint-io/qtap/pkg/config"
	"github.com/qpoint-io/qtap/pkg/process"
	"github.com/qpoint-io/qtap/pkg/telemetry"
	"go.uber.org/zap"
)

type TlsProbe interface {
	Start() error
	Stop() error
	process.Observer
}

type TlsManager struct {
	// logger
	logger *zap.Logger

	// probes
	probes []TlsProbe
}

func NewTlsManager(logger *zap.Logger, probes ...TlsProbe) *TlsManager {
	return &TlsManager{
		// logger
		logger: logger,

		// initialize selected probes
		probes: probes,
	}
}

func (m *TlsManager) Start() error {
	for _, p := range m.probes {
		if err := p.Start(); err != nil {
			return fmt.Errorf("starting tls probe: %w", err)
		}
	}

	telemetry.ObservableGauge("tap_tls_manager_probes",
		func() float64 {
			return float64(len(m.probes))
		},
		telemetry.WithDescription("The number of probes that have started"),
	)

	return nil
}

func (m *TlsManager) Stop() error {
	for _, p := range m.probes {
		if err := p.Stop(); err != nil {
			return fmt.Errorf("stopping tls probe: %w", err)
		}
	}

	return nil
}

func (m *TlsManager) ProcessStarted(proc *process.Process) error {
	// ensure only one scan process happening at a time per process
	proc.ScanLock()
	defer proc.ScanUnlock()

	// check if process is still active
	if proc.Exited() {
		return nil
	}

	// check if the process strategy is observe
	if proc.Strategy != process.StrategyObserve {
		return nil
	}

	// check if process is filtered
	if proc.IsFiltered(config.FilterLevel_TLS) {
		return nil
	}

	// ensure the elf gets closed at the end of the scan
	defer func() {
		if err := proc.CloseElf(); err != nil {
			m.logger.Error("closing elf", zap.Error(err))
		}
	}()

	// inform all probes
	for _, p := range m.probes {
		if proc.Exited() {
			return nil
		}

		if err := p.ProcessStarted(proc); err != nil {
			// if the process was replaced mid scan, just return and let the next one try
			if errors.Is(err, process.ErrProcessReplaced) {
				return nil
			}

			return fmt.Errorf("starting process on tls probe: %w", err)
		}
	}

	return nil
}

func (m *TlsManager) ProcessReplaced(proc *process.Process) error {
	// inform all probes
	for _, p := range m.probes {
		if err := p.ProcessReplaced(proc); err != nil {
			return fmt.Errorf("replacing process on tls probe: %w", err)
		}
	}

	// run process started again
	return m.ProcessStarted(proc)
}

func (m *TlsManager) ProcessStopped(proc *process.Process) error {
	proc.ScanLock()
	defer proc.ScanUnlock()

	for _, p := range m.probes {
		if err := p.ProcessStopped(proc); err != nil {
			return fmt.Errorf("stopping process on tls probe: %w", err)
		}
	}

	return nil
}
