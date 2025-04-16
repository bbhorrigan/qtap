package telemetry

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSnakeCase(t *testing.T) {
	assert.Equal(t, "foo_bar_baz", SnakeCase("foo", "bar", "baz"))
	assert.Equal(t, "foo_bar", SnakeCase("foo", "", "bar", ""))
}
