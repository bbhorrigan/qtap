package config

import (
	_ "embed"
	"fmt"

	"go.uber.org/zap"
)

//go:embed default.yaml
var defaultConfigBytes []byte

// DefaultConfigProvider loads configuration from a local file and reloads on SIGHUP
type DefaultConfigProvider struct {
	logger   *zap.Logger
	cfg      *Config
	callback func(*Config) error
}

// NewDefaultConfigProvider creates a new provider for default config
func NewDefaultConfigProvider(logger *zap.Logger) *DefaultConfigProvider {
	return &DefaultConfigProvider{
		logger: logger,
	}
}

// Start watching for config changes via SIGHUP
func (p *DefaultConfigProvider) Start() error {
	cfg, err := UnmarshalConfig(defaultConfigBytes)
	if err != nil {
		return fmt.Errorf("failed to unmarshal default config: %w", err)
	}

	p.cfg = cfg

	if p.callback != nil {
		return p.callback(p.cfg)
	}

	return nil
}

// Stop watching for config changes
func (p *DefaultConfigProvider) Stop() {}

// OnConfigChange registers a callback for config changes
func (p *DefaultConfigProvider) OnConfigChange(callback func(*Config) error) {
	p.callback = callback
}

// Reload forces a configuration reload
func (p *DefaultConfigProvider) Reload() error {
	return p.callback(p.cfg)
}
