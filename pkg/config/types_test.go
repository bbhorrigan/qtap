package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestValueSourceUnmarshal(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     ValueSource
		wantErr  bool
	}{
		{
			name:     "text value source",
			filename: "testdata/value_source_text.yaml",
			want: ValueSource{
				Type:  ValueSourceType_TEXT,
				Value: "some-text-value",
			},
			wantErr: false,
		},
		{
			name:     "env value source",
			filename: "testdata/value_source_env.yaml",
			want: ValueSource{
				Type:  ValueSourceType_ENV,
				Value: "TEST_ENV_VAR",
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

			var got ValueSource
			err = yaml.Unmarshal(data, &got)
			if (err != nil) != tt.wantErr {
				t.Errorf("yaml.Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestValueSource_String(t *testing.T) {
	const (
		testEnvVar    = "TEST_ENV_VAR"
		testEnvValue  = "env-value"
		testTextValue = "text-value"
	)

	// Set up test environment variable
	t.Setenv(testEnvVar, testEnvValue)

	tests := []struct {
		name string
		vs   ValueSource
		want string
	}{
		{
			name: "text value source",
			vs: ValueSource{
				Type:  ValueSourceType_TEXT,
				Value: testTextValue,
			},
			want: testTextValue,
		},
		{
			name: "env value source",
			vs: ValueSource{
				Type:  ValueSourceType_ENV,
				Value: testEnvVar,
			},
			want: testEnvValue,
		},
		{
			name: "unknown value source type",
			vs: ValueSource{
				Type:  "unknown",
				Value: "some-value",
			},
			want: "",
		},
		{
			name: "env value source with non-existent env var",
			vs: ValueSource{
				Type:  ValueSourceType_ENV,
				Value: "NON_EXISTENT_ENV_VAR",
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.vs.String()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCertUnmarshal(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     Cert
		wantErr  bool
	}{
		{
			name:     "valid cert",
			filename: "testdata/cert_valid.yaml",
			want: Cert{
				Ca:  "ca-cert-data",
				Crt: "certificate-data",
				Key: "private-key-data",
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

			var got Cert
			err = yaml.Unmarshal(data, &got)
			if (err != nil) != tt.wantErr {
				t.Errorf("yaml.Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			assert.Equal(t, tt.want, got)
		})
	}
}
