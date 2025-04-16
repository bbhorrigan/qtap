package dns

import (
	"context"
	"errors"
	"strings"
	"sync"
	"syscall"

	"github.com/qpoint-io/qtap/pkg/connection"
	"github.com/qpoint-io/qtap/pkg/dns"
	"github.com/qpoint-io/qtap/pkg/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/net/dns/dnsmessage"

	"go.uber.org/zap"
)

var tracer = telemetry.Tracer()

type DNSStream struct {
	// context
	ctx context.Context

	// logging
	logger *zap.Logger

	// dns manager
	manager *dns.DNSManager

	// pid
	pid int

	// buffer
	buffer []byte

	// closed
	closed bool

	// mutex
	mu sync.Mutex
}

func NewDNSStream(ctx context.Context, logger *zap.Logger, conn *connection.Connection, dnsManager *dns.DNSManager) *DNSStream {
	ctx, span := tracer.Start(ctx, "Stream")
	span.SetAttributes(attribute.String("stream.type", "dns"))

	s := &DNSStream{
		ctx:     ctx,
		logger:  logger,
		manager: dnsManager,
		pid:     int(conn.OpenEvent.PID),
		buffer:  make([]byte, 0),
	}

	// return the stream
	return s
}

func (t *DNSStream) Process(event *connection.DataEvent) error {
	// ignore queries since the answer contains the query
	if event.Direction == connection.Egress {
		return nil
	}

	// append to the buffer
	t.buffer = append(t.buffer, event.Data...)

	// process DNS message
	t.processDNSMessage()

	return nil
}

func (t *DNSStream) processDNSMessage() {
	var p dnsmessage.Parser
	_, err := p.Start(t.buffer)
	if err != nil {
		return
	}

	questions, err := p.AllQuestions()
	if err != nil {
		return
	}

	// domain to resolve
	var domain string

	if len(questions) > 0 {
		// set on struct for response
		domain = strings.TrimRight(questions[0].Name.String(), ".")

		// debug
		t.logger.Debug("DNS Query", zap.String("hostname", domain))
	}

	// parse answers
	for {
		answer, err := p.Answer()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			t.logger.Error("unpacking DNS answer", zap.Error(err))
			return
		}

		// create a dns record
		record := &dns.Record{
			SaFamily: syscall.AF_INET,
			Domain:   domain,
		}

		// copy the address
		switch rr := answer.Body.(type) {
		case *dnsmessage.AResource:
			copy(record.Addr[:4], rr.A[:])

		case *dnsmessage.AAAAResource:
			copy(record.Addr[:16], rr.AAAA[:])
		}

		// debug
		t.logger.Debug("DNS Response", zap.String("domain", domain), zap.String("ip", record.IpString()))

		// submit to manager
		if t.manager != nil {
			t.manager.Set(record, t.pid)
		}
	}

	// clear the buffer
	t.buffer = t.buffer[len(t.buffer):]
}

func (t *DNSStream) Close() {
	span := trace.SpanFromContext(t.ctx)
	defer span.End()

	t.mu.Lock()
	defer t.mu.Unlock()

	t.closed = true
}

func (t *DNSStream) Closed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.closed
}
