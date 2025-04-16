package auditlog

import (
	"github.com/qpoint-io/qtap/pkg/config"
	"go.uber.org/zap"
)

type Processor struct {
	logger      *zap.Logger
	auditType   config.EventStoreType
	auditLogger *zap.Logger
}

func New(logger *zap.Logger) *Processor {
	return &Processor{
		logger:    logger,
		auditType: config.EventStoreType_CONSOLE,
	}
}

func (p *Processor) Log(fields ...zap.Field) {
	switch p.auditType {
	case config.EventStoreType_DISABLED:
		return
	case config.EventStoreType_CONSOLE:
		p.logger.Info("audit", fields...)
		return
	}
}

func (p *Processor) SetConfig(conf *config.Config) {
	if conf.Tap == nil {
		return
	}

	if !conf.Services.HasAnyEventStores() {
		p.logger.Warn("no event stores configured; audit logs will be discarded")

		return
	}

	al := conf.Services.FirstEventStore()

	if p.auditType != al.Type {
		p.auditType = al.Type
		p.logger.Info("audit log processor audit type changed", zap.String("new type", string(p.auditType)))
	}
}

func (p *Processor) Stop() error {
	return p.auditLogger.Sync()
}
