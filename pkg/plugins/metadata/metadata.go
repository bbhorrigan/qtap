package metadata

import "fmt"

// MetadataValue holds a value of type any.
type MetadataValue struct {
	Value any
}

func (m *MetadataValue) OK() bool {
	return m.Value != nil
}

func (m *MetadataValue) Raw() any {
	return m.Value
}

func (m *MetadataValue) String() string {
	return fmt.Sprintf("%v", m.Value)
}

func (m *MetadataValue) Int64() int64 {
	if m.Value == nil {
		return 0
	}

	switch v := m.Value.(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(v)
	default:
		return 0
	}
}
