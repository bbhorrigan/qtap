package config

import (
	"testing"

	"os"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestEventStoreUnmarshal(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     ServiceEventStore
		wantErr  bool
	}{
		{
			name:     "console eventstore",
			filename: "testdata/eventstore_console.yaml",
			want: ServiceEventStore{
				Type: EventStoreType_CONSOLE,
				ID:   "console-store",
			},
			wantErr: false,
		},
		{
			name:     "pulse eventstore",
			filename: "testdata/eventstore_pulse.yaml",
			want: ServiceEventStore{
				Type: EventStoreType_PULSE,
				ID:   "pulse-store",
				EventStoreConfig: EventStoreConfig{
					EventStorePulseConfig: EventStorePulseConfig{
						URL: "https://pulse.example.com",
						Token: ValueSource{
							Value: "secret-token",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:     "disabled eventstore",
			filename: "testdata/eventstore_disabled.yaml",
			want: ServiceEventStore{
				Type: EventStoreType_DISABLED,
				ID:   "disabled-store",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(tt.filename)
			if err != nil {
				t.Fatalf("failed to read test file: %v", err)
			}

			var got ServiceEventStore
			err = yaml.Unmarshal(data, &got)
			if (err != nil) != tt.wantErr {
				t.Errorf("yaml.Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			assert.Equal(t, tt.want, got)
		})
	}
}
