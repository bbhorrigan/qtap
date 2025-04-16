package config

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

type MatchStrategy string

var (
	MatchStrategy_EXACT    MatchStrategy = "exact"
	MatchStrategy_PREFIX   MatchStrategy = "prefix"
	MatchStrategy_SUFFIX   MatchStrategy = "suffix"
	MatchStrategy_CONTAINS MatchStrategy = "contains"
	MatchStrategy_REGEX    MatchStrategy = "regex"
)

var ValidMatchStrategies = map[MatchStrategy]struct{}{
	MatchStrategy_EXACT:    {},
	MatchStrategy_PREFIX:   {},
	MatchStrategy_SUFFIX:   {},
	MatchStrategy_CONTAINS: {},
	MatchStrategy_REGEX:    {},
}

func (ms *MatchStrategy) Parse(s string) bool {
	strategy := MatchStrategy(s)
	if _, ok := ValidMatchStrategies[strategy]; ok {
		*ms = strategy
		return true
	}
	return false
}

type FilterLevel string

const (
	FilterLevel_DATA FilterLevel = "data"
	FilterLevel_DNS  FilterLevel = "dns"
	FilterLevel_TLS  FilterLevel = "tls"
	FilterLevel_HTTP FilterLevel = "http"
)

func (t FilterLevel) Resolve() uint8 {
	switch t {
	case FilterLevel_DATA:
		return SkipDataFlag
	case FilterLevel_DNS:
		return SkipDNSFlag
	case FilterLevel_TLS:
		return SkipTLSFlag
	case FilterLevel_HTTP:
		return SkipHTTPFlag
	default:
		return 0
	}
}

type TapFilter struct {
	Exe      string        `yaml:"exe"`
	Strategy MatchStrategy `yaml:"strategy"`
	Only     []FilterLevel `yaml:"only,omitempty"`
}

func (tf TapFilter) Validate() error {
	if tf.Exe == "" {
		return errors.New("exe must not be empty")
	}

	if tf.Strategy == MatchStrategy_REGEX {
		_, err := regexp.Compile(tf.Exe)
		if err != nil {
			return fmt.Errorf("invalid regex for exe: %w", err)
		}
	}

	if len(tf.Only) > 0 {
		for _, filter := range tf.Only {
			if filter != FilterLevel_DATA &&
				filter != FilterLevel_DNS &&
				filter != FilterLevel_TLS &&
				filter != FilterLevel_HTTP {
				return fmt.Errorf("invalid filter: %s", filter)
			}
		}
	}

	return nil
}

func (tf TapFilter) Evaluate(input string) (bool, error) {
	if input == "" {
		return false, nil
	}

	input = strings.ToLower(input)
	exe := strings.ToLower(tf.Exe)

	switch tf.Strategy {
	case MatchStrategy_EXACT:
		return exe == input, nil
	case MatchStrategy_PREFIX:
		return strings.HasPrefix(input, exe), nil
	case MatchStrategy_SUFFIX:
		return strings.HasSuffix(input, exe), nil
	case MatchStrategy_CONTAINS:
		return strings.Contains(input, exe), nil
	case MatchStrategy_REGEX:
		re, err := regexp.Compile(exe)
		if err != nil {
			return false, fmt.Errorf("invalid regex: %w", err)
		}
		return re.MatchString(input), nil
	default:
		return strings.HasSuffix(input, exe), nil
	}
}

const (
	SkipDataFlag = 1 << iota
	SkipDNSFlag
	SkipTLSFlag
	SkipHTTPFlag
)

func (tf TapFilter) Pack() uint8 {
	if len(tf.Only) == 0 {
		return SkipDataFlag | SkipDNSFlag | SkipTLSFlag | SkipHTTPFlag
	}

	var flags uint8 = 0

	if slices.Contains(tf.Only, FilterLevel_DATA) {
		flags |= SkipDataFlag
	}
	if slices.Contains(tf.Only, FilterLevel_DNS) {
		flags |= SkipDNSFlag
	}
	if slices.Contains(tf.Only, FilterLevel_TLS) {
		flags |= SkipTLSFlag
	}
	if slices.Contains(tf.Only, FilterLevel_HTTP) {
		flags |= SkipHTTPFlag
	}

	return flags
}

type TapFilters struct {
	Groups []string    `yaml:"groups,omitempty"`
	Custom []TapFilter `yaml:"custom,omitempty"`
}
