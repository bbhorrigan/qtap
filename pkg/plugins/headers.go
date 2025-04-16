package plugins

import (
	"bytes"
	"net/http"
	"sync"
)

var _ HeaderValue = (*Header)(nil)

type Header []byte

func NewHeaderValue(str string) Header {
	return Header([]byte(str))
}

// Bytes implements HeaderValue.
func (h Header) Bytes() []byte {
	return h
}

// Equal implements HeaderValue.
func (h Header) Equal(str string) bool {
	return bytes.Equal(h, []byte(str))
}

// String implements HeaderValue.
func (h Header) String() string {
	return string(h)
}

type HttpHeaderMap struct {
	mu     sync.RWMutex
	header http.Header
}

func NewHeaders(header http.Header) *HttpHeaderMap {
	return &HttpHeaderMap{
		header: header,
	}
}

func (h *HttpHeaderMap) Get(key string) (HeaderValue, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.header != nil {
		val := h.header.Get(key)
		return NewHeaderValue(val), val != ""
	}
	return nil, false
}

func (h *HttpHeaderMap) Values(key string, iter func(value HeaderValue)) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.header != nil {
		for _, value := range h.header.Values(key) {
			iter(NewHeaderValue(value))
		}
	}
}

func (h *HttpHeaderMap) Set(key, value string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.header != nil {
		h.header.Set(key, value)
	}
}

func (h *HttpHeaderMap) Remove(key string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.header != nil {
		h.header.Del(key)
	}
}

func (h *HttpHeaderMap) All() map[string]string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// This follows Go's http.Header.Clone() implementation
	all := make(map[string]string)
	for k, v := range h.header {
		var val string
		if len(v) > 0 {
			val = v[0]
		}
		all[k] = val
	}

	return all
}

func (h *HttpHeaderMap) StdlibHeader() http.Header {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return h.header.Clone()
}
