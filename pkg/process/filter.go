package process

import (
	"fmt"
	"sync"

	"github.com/qpoint-io/qtap/pkg/config"
	"go.uber.org/zap"
)

var filters []config.TapFilter
var filterMu sync.RWMutex

func applyFilters(exe string) uint8 {
	filterMu.RLock()
	defer filterMu.RUnlock()

	for _, filter := range filters {
		match, err := filter.Evaluate(exe)
		if err != nil {
			zap.L().Error("error evaluating filter, continuing",
				zap.String("exe", exe),
				zap.Any("filter", filter),
				zap.Error(err))
			continue
		}

		if match {
			return filter.Pack()
		}
	}

	return 0
}

func (m *Manager) updateFilters(cfg *config.Config) {
	if cfg.Tap == nil {
		return
	}

	var f []config.TapFilter

	// add custom filter
	for _, filter := range cfg.Tap.Filters.Custom {
		if err := filter.Validate(); err != nil {
			m.Logger.Warn("invalid filter; not loading", zap.Any("filter", filter), zap.Error(err))
			continue
		}

		f = append(f, filter)
	}

	// add predefined filters from groups
	for _, group := range cfg.Tap.Filters.Groups {
		f = append(f, getPredefinedFilters(group)...)
	}

	// set the filters
	filterMu.Lock()
	filters = f
	filterMu.Unlock()

	// debug
	m.Logger.Debug("applying filters to existing processes", zap.Any("filters", filters))

	// check existing exe map for existing pids and set the flags accordingly
	m.procs.Iter(func(pid int, p *Process) bool {
		if f := applyFilters(p.Exe); f != 0 {
			// add to the bpf map
			p.filter = f
			if p.notifier != nil {
				if err := p.notifier(); err != nil {
					m.Logger.Warn("failed to notify eventer",
						zap.Int("pid", pid),
						zap.String("exe", p.Exe),
						zap.Any("flag", f),
						zap.Error(err))
				}
			}

			// debug
			m.Logger.Debug("filtering existing process",
				zap.Int("pid", pid),
				zap.String("exe", p.Exe),
				zap.String("flag", fmt.Sprintf("%08b", f)))
		}

		// continue iterating
		return true
	})
}
