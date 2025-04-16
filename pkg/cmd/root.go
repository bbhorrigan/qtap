package cmd

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/qpoint-io/qtap/pkg/buildinfo"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/term"
)

var (
	// Global flags
	dataDir               string
	qpointConfig          string
	auditLogBufferSize    int
	deploymentTags        string
	logLevel              string
	logEncoding           string
	logCaller             bool
	statusListen          string
	bpfTraceQuery         string
	certInjectionStrategy string
	tlsOkStrategy         string

	rootCmd = &cobra.Command{
		Use:     "qpoint",
		Short:   "A Qpoint utility to tap and/or proxy your web traffic streams",
		Version: buildinfo.Version(),
		Run: func(cmd *cobra.Command, args []string) {
			tapCmd.Run(cmd, args)
		},
	}
)

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Logging options
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level",
		getEnvOr("LOG_LEVEL", "info"),
		"Log level (debug, info, warn, error, dpanic, panic, fatal)")
	rootCmd.PersistentFlags().StringVar(&logEncoding, "log-encoding",
		getEnvOr("LOG_ENCODING", defaultLogEncoding()),
		"Log encoding (console, json)")
	rootCmd.PersistentFlags().BoolVar(&logCaller, "log-caller",
		getEnvBoolOr("LOG_CALLER", false),
		"Log caller")

	// Add commands
	rootCmd.AddCommand(tapCmd)
	rootCmd.AddCommand(reloadConfigCmd)
}

// defaultLogEncoding determines the default log encoding based on whether stdout is a terminal
func defaultLogEncoding() string {
	if term.IsTerminal(int(os.Stdout.Fd())) {
		return "console"
	}
	return "json"
}

// getEnvBoolOr returns environment variable as bool or default if not set
func getEnvBoolOr(key string, defaultValue bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		if value == "true" || value == "1" {
			return true
		}
		if value == "false" || value == "0" {
			return false
		}
	}
	return defaultValue
}

// getEnvOr returns environment variable value or default if not set
func getEnvOr(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// getEnvIntOr returns environment variable as int or default if not set
func getEnvIntOr(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func convertStringToZapLevel(levelStr string) (zapcore.Level, error) {
	var l zapcore.Level
	err := l.UnmarshalText([]byte(levelStr))
	if err != nil {
		return 0, fmt.Errorf("invalid log level: %s", levelStr)
	}
	return l, nil
}

func initLogger() *zap.Logger {
	level, err := convertStringToZapLevel(logLevel)
	if err != nil {
		panic("error: invalid log level: " + err.Error())
	}

	cfg := zap.NewProductionConfig()
	cfg.DisableCaller = !logCaller
	cfg.Level = zap.NewAtomicLevelAt(level)
	cfg.Encoding = logEncoding
	cfg.EncoderConfig.MessageKey = "message"

	if strings.EqualFold(logEncoding, "console") {
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		cfg.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("2006-01-02 15:04:05.000")
	}

	l, err := cfg.Build()
	if err != nil {
		panic("error: couldn't create a logger: " + err.Error())
	}

	// Replace the global logger with the one we just created
	// This can be accessed via zap.L()
	zap.ReplaceGlobals(l)

	return l
}

func syncLogger(logger *zap.Logger) {
	// The EINVAL error catch is a
	// workaround for https://github.com/uber-go/zap/issues/772
	if err := logger.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) {
		fmt.Fprintf(os.Stderr, "syncing logger: %v\n", err)
		return
	}
}
