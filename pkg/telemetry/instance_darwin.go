package telemetry

import (
	"errors"

	"go.uber.org/zap"
)

func GetSysInfo() (map[string]map[string]string, error) {
	return nil, errors.New("not implemented")
}

func GetSysInfoAsFields() zap.Field {
	return zap.Field{}
}
