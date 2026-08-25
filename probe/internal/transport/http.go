// Package transport implements the probe -> detector NDJSON transport.
//
// Events are buffered, batched up to BatchSize or FlushInterval (whichever
// comes first), and POSTed as application/x-ndjson. The detector's expected
// endpoint is /events; the request body is one JSON event per line.
//
// Retries use exponential backoff capped at 5s. 4xx responses are logged
// and dropped (malformed event batch — the probe shouldn't retry indefinitely).
// 5xx and network errors are retried. The buffer is bounded; if the consumer
// stops accepting, Send blocks until the receiver catches up or ctx is done.
package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/shadowkube-repro/pkg/event"
)

// Transport is the abstract sink for events.
type Transport interface {
	// Send enqueues an event for delivery. Blocks if the buffer is full.
	Send(ctx context.Context, ev event.Event) error
	// Close flushes any pending events and releases resources.
	Close() error
}

// HttpTransport posts events to detectorURL/events as NDJSON batches.
type HttpTransport struct {
	url           string
	batchSize     int
	flushInterval time.Duration
	client        *http.Client

	mu     sync.Mutex
	buf    []event.Event
	closed bool
	wake   chan struct{} // size-1, signaled on new event or close
}

// New constructs an HttpTransport.
func New(url string, batchSize int, flushInterval time.Duration) *HttpTransport {
	return &HttpTransport{
		url:           url,
		batchSize:     batchSize,
		flushInterval: flushInterval,
		client:        &http.Client{Timeout: 10 * time.Second},
		buf:           make([]event.Event, 0, batchSize),
		wake:          make(chan struct{}, 1),
	}
}

// Run owns the flush loop. It exits when ctx is done or Close is called and
// the buffer is empty.
func (t *HttpTransport) Run(ctx context.Context) error {
	ticker := time.NewTicker(t.flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			t.flush(ctx) // best-effort drain
			return ctx.Err()
		case <-ticker.C:
			t.flush(ctx)
		case <-t.wake:
			// woke because the buffer hit batchSize
			if t.bufferedLen() >= t.batchSize {
				t.flush(ctx)
			}
		}
	}
}

// Send appends ev to the buffer. Returns an error if the transport is closed.
func (t *HttpTransport) Send(ctx context.Context, ev event.Event) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return fmt.Errorf("transport closed")
	}
	t.buf = append(t.buf, ev)
	full := len(t.buf) >= t.batchSize
	t.mu.Unlock()

	if full {
		select {
		case t.wake <- struct{}{}:
		default:
		}
	}
	return nil
}

// Close flushes any pending events and marks the transport closed.
func (t *HttpTransport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	t.mu.Unlock()

	// Wake the flush loop one last time.
	select {
	case t.wake <- struct{}{}:
	default:
	}
	return nil
}

func (t *HttpTransport) bufferedLen() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.buf)
}

// flush sends the current batch with exponential-backoff retries.
func (t *HttpTransport) flush(ctx context.Context) {
	t.mu.Lock()
	if len(t.buf) == 0 {
		t.mu.Unlock()
		return
	}
	batch := t.buf
	t.buf = make([]event.Event, 0, t.batchSize)
	t.mu.Unlock()

	var body bytes.Buffer
	for _, ev := range batch {
		b, err := json.Marshal(ev)
		if err != nil {
			log.Printf("transport: marshal: %v (event=%+v)", err, ev)
			continue
		}
		body.Write(b)
		body.WriteByte('\n')
	}

	backoff := 200 * time.Millisecond
	for attempt := 1; attempt <= 5; attempt++ {
		if ctx.Err() != nil {
			return
		}
		err := t.post(ctx, body.Bytes())
		if err == nil {
			return
		}
		// 4xx: don't retry, the server told us it's malformed.
		if isClientError(err) {
			log.Printf("transport: dropping batch of %d events (4xx): %v", len(batch), err)
			return
		}
		log.Printf("transport: attempt %d failed: %v (retry in %s)", attempt, err, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > 5*time.Second {
			backoff = 5 * time.Second
		}
	}
	log.Printf("transport: giving up on batch of %d events after 5 attempts", len(batch))
}

func (t *HttpTransport) post(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return clientError{status: resp.StatusCode, body: readAll(resp.Body)}
	}
	return fmt.Errorf("server returned %d: %s", resp.StatusCode, readAll(resp.Body))
}

type clientError struct {
	status int
	body   string
}

func (e clientError) Error() string { return fmt.Sprintf("client error %d: %s", e.status, e.body) }

func isClientError(err error) bool {
	_, ok := err.(clientError)
	return ok
}

func readAll(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 4096))
	return string(b)
}
