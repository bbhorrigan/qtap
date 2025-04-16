package console

import (
	"context"
	"fmt"

	"github.com/qpoint-io/qtap/pkg/services"
	"github.com/qpoint-io/qtap/pkg/services/eventstore"
	"github.com/qpoint-io/qtap/pkg/services/objectstore"
	"go.uber.org/zap"
)

const (
	TypeConsoleEventStore services.ServiceType = "console"
)

type Factory struct {
	objectstore.BaseObjectStore
}

func (f *Factory) Init(ctx context.Context, cfg any) error {
	return nil
}

func (f *Factory) Create(ctx context.Context) (services.Service, error) {
	return &ObjectStore{}, nil
}

func (f *Factory) FactoryType() services.ServiceType {
	return services.ServiceType(fmt.Sprintf("%s.%s", objectstore.TypeObjectStore, TypeConsoleEventStore))
}

type ObjectStore struct {
	services.LogHelper
	objectstore.BaseObjectStore
}

func (s *ObjectStore) Put(ctx context.Context, artifact eventstore.Artifact) (*eventstore.ArtifactRecord, error) {
	s.Log().Debug("object store submission",
		zap.String("digest", artifact.Digest()),
		zap.Any("artifact", artifact),
	)

	return artifact.Record("stdout://" + artifact.Digest()), nil
}
