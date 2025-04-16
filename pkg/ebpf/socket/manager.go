package socket

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/qpoint-io/qtap/pkg/connection"
	"github.com/qpoint-io/qtap/pkg/ebpf/common"
	"github.com/qpoint-io/qtap/pkg/telemetry"
	"go.uber.org/zap"
)

type ConnectionEventHandler interface {
	HandleEvent(event connection.Keyer)
}

// SocketEventManager accepts generic socket events
// and coordinates them into the respective transactions.
type SocketEventManager struct {
	// bridge to the bpf probes
	probes   []common.Probe
	rdEvents *ringbuf.Reader

	// internal components
	logger       *zap.Logger
	eventHandler ConnectionEventHandler
}

func NewSocketEventManager(logger *zap.Logger, handler ConnectionEventHandler, rb *ringbuf.Reader, probes []common.Probe) *SocketEventManager {
	// init a manager
	m := &SocketEventManager{
		logger:       logger,
		eventHandler: handler,
		rdEvents:     rb,
		probes:       probes,
	}

	return m
}

func (m *SocketEventManager) Start() error {
	// attach the probes
	for _, probe := range m.probes {
		if err := probe.Attach(); err != nil {
			return fmt.Errorf("attaching probe %s: %w", probe.ID(), err)
		}
	}

	// start the event reader
	go m.readEvents()

	// start telemetry
	if err := m.startTelemetry(); err != nil {
		return fmt.Errorf("starting telemetry: %w", err)
	}

	return nil
}

func (m *SocketEventManager) Stop() error {
	// close the reader
	m.rdEvents.Close()

	// detach the probes
	for _, probe := range m.probes {
		if err := probe.Detach(); err != nil {
			return fmt.Errorf("detaching probe %s: %w", probe.ID(), err)
		}
	}

	return nil
}

var recordPool = sync.Pool{
	New: func() interface{} {
		return new(ringbuf.Record)
	},
}

func (m *SocketEventManager) readEvents() {
	for {
		record := recordPool.Get().(*ringbuf.Record)
		err := m.rdEvents.ReadInto(record)
		if err != nil {
			recordPool.Put(record)

			if errors.Is(err, os.ErrClosed) {
				break
			}
			m.logger.Error("failed to read from buffer", zap.Error(err))
		}

		err = m.readEvent(record)
		if err != nil {
			recordPool.Put(record)

			m.logger.Error("failed to read event", zap.Error(err))
		}

		recordPool.Put(record)
	}
}

func (m *SocketEventManager) startTelemetry() error {
	telemetry.ObservableGauge(
		"tap_socket_probes",
		func() float64 {
			return float64(len(m.probes))
		},
		telemetry.WithDescription("The number of probes currently being tracked"),
	)

	return nil
}
