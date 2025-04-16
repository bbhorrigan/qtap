package accesslogs

import (
	"io"
	"os"
	"time"

	"github.com/qpoint-io/qtap/pkg/plugins"
	"github.com/qpoint-io/qtap/pkg/services"

	"github.com/qpoint-io/rulekit"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/yaml.v3"
)

const (
	pluginTypeAccessLogs plugins.PluginType = "access_logs"
	pluginTypeDebug      plugins.PluginType = "debug"
)

var (
	accessLogsWriter io.Writer = os.Stdout
)

type factory struct {
	pluginType plugins.PluginType
	format     outputFormat
	logger     *zap.Logger
	writer     *zap.Logger
	config     *AccessLogConfig
}

type AccessLogConfig struct {
	Mode   displayMode  `json:"mode" yaml:"mode"`     // summary, details, full
	Format outputFormat `json:"format" yaml:"format"` // json, console
	Rules  []logRule    `json:"rules" yaml:"rules"`
}

func NewConsoleJSONFilter() plugins.HttpPlugin {
	return &factory{
		pluginType: pluginTypeAccessLogs,
		format:     outputFormatJSON,
	}
}

func NewConsoleHttpFilter() plugins.HttpPlugin {
	return &factory{
		pluginType: pluginTypeDebug,
		format:     outputFormatConsole,
	}
}

func (f *factory) Init(logger *zap.Logger, config yaml.Node) {
	f.logger = logger
	f.writer = createWriter(accessLogsWriter)
	f.config = &AccessLogConfig{}

	// parse
	var cfg AccessLogConfig
	if err := config.Decode(&cfg); err != nil {
		logger.Error("error decoding config", zap.Error(err))
		return
	}

	if cfg.Format == "" {
		cfg.Format = f.format
	}

	for i := range cfg.Rules {
		var err error
		cfg.Rules[i].rule, err = rulekit.Parse(cfg.Rules[i].Expr)
		if err != nil {
			logger.Error("error parsing log rule", zap.Error(err))
		}
	}

	f.config = &cfg
}

func (f *factory) NewInstance(ctx plugins.PluginContext, svcs ...services.Service) plugins.HttpPluginInstance {
	f.logger.Debug("new plugin instance created")
	return &filterInstance{
		ctx: ctx,

		logger: f.logger,
		writer: f.writer,

		mode:   f.config.Mode,
		format: f.config.Format,
		rules:  f.config.Rules,
	}
}

func (f *factory) RequiredServices() []services.ServiceType {
	return nil
}

func (f *factory) Destroy() {
	f.logger.Debug("filter destroyed")
}

func createWriter(writer io.Writer) *zap.Logger {
	encoderConfig := zapcore.EncoderConfig{
		MessageKey:     "msg",
		LevelKey:       "", // Remove level
		TimeKey:        "", // Remove time
		NameKey:        "", // Remove logger name
		CallerKey:      "", // Remove caller
		StacktraceKey:  "", // Remove stacktrace
		LineEnding:     "",
		EncodeLevel:    func(level zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {},
		EncodeTime:     func(time.Time, zapcore.PrimitiveArrayEncoder) {},
		EncodeDuration: func(d time.Duration, enc zapcore.PrimitiveArrayEncoder) {},
		EncodeCaller:   func(caller zapcore.EntryCaller, enc zapcore.PrimitiveArrayEncoder) {},
	}

	// create a core that writes logs to the io.Writer
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		zapcore.AddSync(writer),
		zapcore.InfoLevel,
	)

	// create the logger
	logger := zap.New(core)

	return logger
}

func (f *factory) PluginType() plugins.PluginType {
	if f.pluginType == "" {
		return pluginTypeAccessLogs
	}
	return f.pluginType
}
