package process

import (
	"testing"

	"github.com/qpoint-io/qtap/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateTapFilter(t *testing.T) {
	tests := []struct {
		name        string
		filterStr   string
		want        *config.TapFilter
		wantErr     bool
		errContains string
	}{
		{
			name:      "valid contains filter",
			filterStr: "exe.contains:java",
			want: &config.TapFilter{
				Exe:      "java",
				Strategy: config.MatchStrategy_CONTAINS,
			},
			wantErr: false,
		},
		{
			name:      "valid exact filter",
			filterStr: "exe.exact:java",
			want: &config.TapFilter{
				Exe:      "java",
				Strategy: config.MatchStrategy_EXACT,
			},
			wantErr: false,
		},
		{
			name:      "valid prefix filter",
			filterStr: "exe.prefix:java",
			want: &config.TapFilter{
				Exe:      "java",
				Strategy: config.MatchStrategy_PREFIX,
			},
			wantErr: false,
		},
		{
			name:      "valid suffix filter",
			filterStr: "exe.suffix:java",
			want: &config.TapFilter{
				Exe:      "java",
				Strategy: config.MatchStrategy_SUFFIX,
			},
			wantErr: false,
		},
		{
			name:      "valid regex filter",
			filterStr: "exe.regex:java.*",
			want: &config.TapFilter{
				Exe:      "java.*",
				Strategy: config.MatchStrategy_REGEX,
			},
			wantErr: false,
		},
		{
			name:        "invalid format - missing colon",
			filterStr:   "exe.contains",
			wantErr:     true,
			errContains: "invalid filter format",
		},
		{
			name:        "invalid format - missing dot",
			filterStr:   "exe:java",
			wantErr:     true,
			errContains: "invalid match strategy",
		},
		{
			name:        "empty filter string",
			filterStr:   "",
			wantErr:     true,
			errContains: "invalid filter format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := createTapFilter(tt.filterStr)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, got)
			assert.Equal(t, tt.want.Exe, got.Exe)
			assert.Equal(t, tt.want.Strategy, got.Strategy)
		})
	}
}

func TestQpointStrategyFromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		exe     string
		want    QpointStrategy
		wantErr bool
	}{
		{
			name:  "simple observe strategy",
			input: "observe",
			exe:   "test",
			want:  StrategyObserve,
		},
		{
			name:  "simple ignore strategy",
			input: "ignore",
			exe:   "test",
			want:  StrategyIgnore,
		},
		{
			name:  "simple audit strategy",
			input: "audit",
			exe:   "test",
			want:  StrategyAudit,
		},
		{
			name:  "simple forward strategy",
			input: "forward",
			exe:   "test",
			want:  StrategyForward,
		},
		{
			name:  "simple proxy strategy",
			input: "proxy",
			exe:   "test",
			want:  StrategyProxy,
		},
		{
			name:  "unknown strategy defaults to observe",
			input: "unknown",
			exe:   "test",
			want:  StrategyObserve,
		},
		{
			name:  "matching exact filter",
			input: "proxy,exe.exact:test",
			exe:   "test",
			want:  StrategyProxy,
		},
		{
			name:  "non-matching exact filter defaults to observe",
			input: "proxy,exe.exact:other",
			exe:   "test",
			want:  StrategyObserve,
		},
		{
			name:    "invalid filter format",
			input:   "proxy,invalid_filter",
			exe:     "test",
			want:    StrategyObserve,
			wantErr: true,
		},
		{
			name:  "multiple matching filters - first matches",
			input: "proxy,exe.contains:te,exe.suffix:st",
			exe:   "test",
			want:  StrategyProxy,
		},
		{
			name:  "multiple matching filters - second matches",
			input: "proxy,exe.contains:other,exe.suffix:test",
			exe:   "test",
			want:  StrategyProxy,
		},
		{
			name:  "multiple non-matching filters defaults to observe",
			input: "proxy,exe.contains:other,exe.suffix:fail",
			exe:   "test",
			want:  StrategyObserve,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := QpointStrategyFromString(tt.input, tt.exe)
			if (err != nil) != tt.wantErr {
				t.Errorf("QpointStrategyFromString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("QpointStrategyFromString() = %v, want %v", got, tt.want)
			}
		})
	}
}
