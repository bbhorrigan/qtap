package config

type SentinelType string

const (
	SentinelType_DISABLED SentinelType = "disabled"
	SentinelType_CONSOLE  SentinelType = "stdout"
	SentinelType_Client   SentinelType = "client"
)

type ServiceSentinel struct {
	Type  SentinelType `yaml:"type" validate:"required"`
	URL   string       `yaml:"url"`
	Token ValueSource  `yaml:"token"`
}

func (s ServiceSentinel) ServiceType() string {
	switch s.Type {
	case SentinelType_CONSOLE:
		return "sentinel.console"
	case SentinelType_Client:
		return "sentinel.client"
	case SentinelType_DISABLED:
		return "sentinel.noop"
	default:
		return "sentinel.console"
	}
}
