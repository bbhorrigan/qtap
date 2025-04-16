package tags

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

type List interface {
	Add(string, string)
	AddString(string) error
	List() []string
	Clone() List
	Merge(List)
}

type tags struct {
	mu   sync.RWMutex
	data map[string][]string
}

func New() *tags {
	return &tags{
		data: make(map[string][]string),
	}
}

func FromValues(kv map[string]string) List {
	t := New()

	t.mu.Lock()
	defer t.mu.Unlock()
	for k, v := range kv {
		t.add(k, v)
	}
	return t
}

// Add associates a value with a key in the tags collection. Both key and value are normalized by:
// - Trimming whitespace
// - Converting to lowercase
// - Replacing spaces with hyphens
// The function silently returns without adding if either:
// - Key or value is empty after trimming
// - Key or value doesn't start and end with alphanumeric characters
func (t *tags) Add(key, value string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.add(key, value)
}

func (t *tags) add(key, value string) {
	// Trim whitespace from both key and value
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)

	// Validate non-empty strings
	if key == "" || value == "" {
		return
	}

	// Convert to lowercase
	key = strings.ToLower(key)
	value = strings.ToLower(value)

	// Replace spaces with hyphens
	key = strings.ReplaceAll(key, " ", "-")
	value = strings.ReplaceAll(value, " ", "-")

	// Validate starts and ends with alphanumeric
	if !isAlphanumeric(rune(key[0])) || !isAlphanumeric(rune(key[len(key)-1])) ||
		!isAlphanumeric(rune(value[0])) || !isAlphanumeric(rune(value[len(value)-1])) {
		return
	}

	t.data[key] = append(t.data[key], value)
}

func isAlphanumeric(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
}

func (t *tags) List() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var list []string
	for key, values := range t.data {
		for _, value := range values {
			list = append(list, fmt.Sprintf("%s:%s", key, value))
		}
	}
	return list
}

func (t *tags) AddString(s string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.addString(s)
}

func (t *tags) addString(s string) error {
	key, value, found := strings.Cut(s, ":")
	if !found {
		return errors.New("invalid tag format: must be in the format key:value")
	}
	t.add(key, value)
	return nil
}

// Clone returns a deep copy of the tags collection
func (t *tags) Clone() List {
	t.mu.RLock()
	defer t.mu.RUnlock()

	clone := New()
	for key, values := range t.data {
		clone.data[key] = append([]string{}, values...)
	}
	return clone
}

// Merge combines the tags from another List into this one
func (t *tags) Merge(other List) {
	if other == nil {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	for _, tag := range other.List() {
		_ = t.addString(tag)
	}
}
