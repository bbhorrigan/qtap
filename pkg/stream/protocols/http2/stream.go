package http2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"

	"github.com/qpoint-io/qtap/pkg/connection"
	"github.com/qpoint-io/qtap/pkg/plugins"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// HTTP/2 Frame Header Format (9 bytes total)
//
// +-----------------------------------------------+
// |                 Length (24)                    |
// +---------------+---------------+---------------+
// |   Type (8)    |   Flags (8)   |
// +-+-------------+---------------+-------------------------------+
// |R|                 Stream Identifier (31)                      |
// +=+=============================================================
// |                   Frame Payload (0...)                      ...
// +-----------------------------------------------------------+
//
// Length:    3 bytes - Payload length (not including 9-byte header)
// Type:      1 byte  - Frame type (DATA=0x0, HEADERS=0x1, etc.)
// Flags:     1 byte  - Frame-type specific flags
// R:         1 bit   - Reserved bit
// Stream ID: 31 bits - Stream identifier (0 for connection control)
const frameHeaderLen = 9

// HTTPStream manages the read/write & open/close events
// for an http req/res connection stream based on socket events.
type HTTPStream struct {
	// context
	ctx context.Context

	// logging
	logger *zap.Logger

	// connection domain
	domain string

	// indicates if the preface has been read
	prefaceRead bool

	// plugin manager
	pluginManager *plugins.Manager

	// a buffer
	buffer []byte

	// socket connection
	conn *connection.Connection

	// sessions
	sessions map[uint32]*Session

	// HTTP/2 read meta headers decoder
	headerDecoder *hpack.Decoder

	// closed
	closed bool

	// mutex
	mu sync.Mutex
}

type HTTPStreamOpt func(*HTTPStream)

func SetPluginManager(manager *plugins.Manager) HTTPStreamOpt {
	return func(s *HTTPStream) {
		s.pluginManager = manager
	}
}

func NewHTTPStream(ctx context.Context, domain string, logger *zap.Logger, conn *connection.Connection, opts ...HTTPStreamOpt) *HTTPStream {
	ctx, span := tracer.Start(ctx, "http2.Stream")
	span.SetAttributes(attribute.String("stream.type", "http2"))
	// init a stream
	s := &HTTPStream{
		ctx:      ctx,
		logger:   logger,
		domain:   domain,
		conn:     conn,
		sessions: map[uint32]*Session{},
	}

	// set options
	for _, opt := range opts {
		opt(s)
	}

	// initialize the header decoder
	s.headerDecoder = hpack.NewDecoder(4096, nil)

	// return the stream
	return s
}

func (s *HTTPStream) Process(event *connection.DataEvent) error {
	span := trace.SpanFromContext(s.ctx)
	s.mu.Lock()
	defer s.mu.Unlock()

	// if the stream is closed, do nothing
	if s.closed {
		return nil
	}

	s.buffer = append(s.buffer, event.Data...)

	// read the preface if we haven't already
	if !s.prefaceRead && event.Direction == connection.Egress {
		if err := s.readPreface(); err != nil {
			return connection.ErrStreamUnrecoverable(err)
		}

		s.prefaceRead = true
	}

	for len(s.buffer) > 0 {
		// Need at least 9 bytes for the frame header
		if len(s.buffer) < frameHeaderLen {
			return nil
		}

		// Parse the frame length from the first 3 bytes (big endian)
		frameLength := int(s.buffer[0])<<16 | int(s.buffer[1])<<8 | int(s.buffer[2])

		// Calculate total frame size (header + payload)
		totalFrameSize := frameLength + frameHeaderLen

		// Check if we have the complete frame
		if len(s.buffer) < totalFrameSize {
			return nil
		}

		// Now we can safely process the complete frame
		framer := http2.NewFramer(nil, bytes.NewReader(s.buffer[:totalFrameSize]))
		frame, err := framer.ReadFrame()
		if err != nil {
			span.AddEvent("http2.frame[error]", trace.WithAttributes(
				attribute.String("error", err.Error()),
				attribute.Int("length", frameLength),
			))
			// stop if the protocol is unrecognized
			if errors.Is(err, http2.ConnectionError(http2.ErrCodeProtocol)) {
				s.conn.Protocol = connection.Protocol_UNKNOWN

				// we want to drop data frames for GRPC streams
				// since plugins do not support it
				return connection.ErrStreamUnrecoverable(fmt.Errorf("http2 unknown protocol format; likely gRPC or a custom HTTP/2 implementation: %w", err))
			}

			return connection.ErrStreamUnrecoverable(fmt.Errorf("error reading http2 frame: %w", err))
		}
		// Remove the processed frame from buffer
		s.buffer = s.buffer[totalFrameSize:]

		frameType := strings.TrimPrefix(reflect.TypeOf(frame).String(), "*http2.")
		span.AddEvent(fmt.Sprintf("http2.frame[%s]", frameType), trace.WithAttributes(
			attribute.Int64("stream_id", int64(frame.Header().StreamID)),
			attribute.Int("length", frameLength),
		))

		// session
		session := s.initSession(frame.Header().StreamID)

		// update the bytes
		if event.Direction == connection.Ingress {
			session.rdBytes += int64(totalFrameSize)
		} else {
			session.wrBytes += int64(totalFrameSize)
		}

		err = s.handleFrame(session, frame, framer)
		if err != nil {
			return err
		}

		// If we have consumed all the buffer, exit the loop
		if len(s.buffer) == 0 {
			break
		}
	}

	return nil
}

func (s *HTTPStream) readPreface() error {
	// first, read the client connection preface
	clientPreface := []byte(http2.ClientPreface)
	prefaceBuffer := make([]byte, len(clientPreface))

	_, err := io.ReadFull(bytes.NewReader(s.buffer), prefaceBuffer)
	if err != nil {
		return fmt.Errorf("failed to read http2 client preface: %w", err)
	}

	if !bytes.Equal(prefaceBuffer, clientPreface) {
		return fmt.Errorf("invalid http2 client preface: %s != %s", string(clientPreface), string(prefaceBuffer))
	}

	// remove the preface from the buffer
	if len(s.buffer) > len(clientPreface) {
		s.buffer = s.buffer[len(clientPreface):]
	} else {
		s.buffer = nil
	}

	return nil
}

func (t *HTTPStream) initSession(streamID uint32) *Session {
	// fetch the session
	session, exists := t.sessions[streamID]

	// create a new session if it doesn't exist
	if !exists {
		// create a new session
		session = NewSession(t.ctx, streamID, t.domain, t.logger, t.conn, t.pluginManager)

		// set the session on the map
		t.sessions[streamID] = session
	}

	// return the session
	return session
}

func (t *HTTPStream) cleanupSession(session *Session) {
	// let the session clean itself up
	session.Close()

	// remove the session from the map
	delete(t.sessions, session.ID)
}

func (t *HTTPStream) handleFrame(session *Session, frame http2.Frame, framer *http2.Framer) error {
	// process the frame
	switch f := frame.(type) {
	case *http2.HeadersFrame:
		mh, err := t.readMetaFrame(f, framer)
		if err != nil {
			t.logger.Error("Failed to read meta headers frame",
				zap.Any("mh", mh),
				zap.Error(err))
			return connection.ErrStreamUnrecoverable(fmt.Errorf("failed to read meta headers frame: %w", err))
		}

		if t.isGRPC(mh) {
			t.conn.Protocol = connection.Protocol_GRPC
			t.logger.Debug("HTTP/2 GRPC detected, closing stream")

			// we want to drop data frames for GRPC streams
			// since plugins do not support it
			return connection.ErrStreamUnrecoverable(errors.New("grpc stream; not supported"))
		}

		return t.handleHeadersFrame(session, mh)

	case *http2.DataFrame:
		return t.handleDataFrame(session, f)
	case *http2.RSTStreamFrame:
		t.cleanupSession(session)
	case *http2.GoAwayFrame:
		t.cleanupSession(session)
	}

	return nil
}

func (t *HTTPStream) handleHeadersFrame(session *Session, frame *http2.MetaHeadersFrame) error {
	switch session.State {
	case StreamStateIdle: // request is started
		// create request
		if err := session.CreateRequest(frame.Fields, frame.StreamEnded()); err != nil {
			t.logger.Error("Failed to create http2 request", zap.Error(err))
			return connection.ErrStreamUnrecoverable(fmt.Errorf("failed to create http2 request: %w", err))
		}

		if frame.StreamEnded() {
			// request is done reading body (no body in this case)
			if err := session.WriteRequestBody(nil, true); err != nil {
				if errors.Is(err, ErrEncodedBody) {
					return connection.ErrStreamUnrecoverable(errors.New("request body is encoded; not supported"))
				}

				t.logger.Error("Failed to write http2 request body", zap.Error(err))
				return connection.ErrStreamUnrecoverable(fmt.Errorf("failed to write http2 request body: %w", err))
			}

			// request is done
			session.SetState(StreamStateRequestDone)
		} else {
			// request is reading body
			session.SetState(StreamStateRequestHeaders)
		}
	case StreamStateRequestDone: // response is started
		// create response
		if err := session.CreateResponse(frame.Fields, frame.StreamEnded()); err != nil {
			t.logger.Error("Failed to create http2 response", zap.Error(err))
			return connection.ErrStreamUnrecoverable(fmt.Errorf("failed to create http2 response: %w", err))
		}

		if frame.StreamEnded() {
			// response is done reading body (no body in this case)
			if err := session.WriteResponseBody(nil, true); err != nil {
				if errors.Is(err, ErrEncodedBody) {
					return connection.ErrStreamUnrecoverable(errors.New("response body is encoded; not supported"))
				}

				t.logger.Error("Failed to write http2 response body", zap.Error(err))
				return connection.ErrStreamUnrecoverable(fmt.Errorf("failed to write http2 response body: %w", err))
			}

			// response is done
			session.SetState(StreamStateResponseDone)

			// cleanup the session
			delete(t.sessions, session.ID)
		} else {
			// response is reading body
			session.SetState(StreamStateResponseHeaders)
		}
	}

	return nil
}

func (t *HTTPStream) handleDataFrame(session *Session, frame *http2.DataFrame) error {
	switch session.State {
	case StreamStateRequestHeaders, StreamStateRequestBody: // request is reading body
		// write the request body
		if err := session.WriteRequestBody(frame.Data(), frame.StreamEnded()); err != nil {
			if errors.Is(err, ErrEncodedBody) {
				return connection.ErrStreamUnrecoverable(errors.New("request body is encoded; not supported"))
			}

			t.logger.Error("Failed to write http2 request body", zap.Error(err))
			return connection.ErrStreamUnrecoverable(fmt.Errorf("failed to write http2 request body: %w", err))
		}

		if frame.StreamEnded() {
			// request is done reading body
			session.SetState(StreamStateRequestDone)
		} else {
			// request is reading body
			session.SetState(StreamStateRequestBody)
		}
	case StreamStateResponseHeaders, StreamStateResponseBody: // response is reading body
		// write the response body
		if err := session.WriteResponseBody(frame.Data(), frame.StreamEnded()); err != nil {
			if errors.Is(err, ErrEncodedBody) {
				return connection.ErrStreamUnrecoverable(errors.New("response body is encoded; not supported"))
			}

			t.logger.Error("Failed to write http2 response body", zap.Error(err))
			return connection.ErrStreamUnrecoverable(fmt.Errorf("failed to write http2 response body: %w", err))
		}

		if frame.StreamEnded() {
			// response is done reading body
			session.SetState(StreamStateResponseDone)
		} else {
			// response is reading body
			session.SetState(StreamStateResponseBody)
		}
	}

	return nil
}

func (t *HTTPStream) Close() {
	span := trace.SpanFromContext(t.ctx)
	defer span.End()

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return
	}

	for _, session := range t.sessions {
		session.Close()
	}

	t.closed = true
	t.buffer = nil
}

func (t *HTTPStream) Closed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.closed
}

func (t *HTTPStream) isGRPC(h *http2.MetaHeadersFrame) bool {
	for _, field := range h.Fields {
		if field.Name == "content-type" && field.Value == "application/grpc" {
			return true
		}
	}

	return false
}
