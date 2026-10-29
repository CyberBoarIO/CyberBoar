// Package ship sends an endpoint's audit log to the console
// (POST /api/v1/events). The hook itself never talks to the network. It only
// appends to a local file, and shipping runs separately, so a slow or
// unreachable console can't delay or block a tool call.
//
// Delivery is at least once. The file offset is saved only after the console
// accepted a batch, so a lost response means the batch is sent again. The
// client authenticates the endpoint and checks that an acceptance really
// comes from the console (package enroll), so a forged one can't make events disappear.
package ship

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"cyberboar.dev/cyberboar/internal/endpoint/enroll"
	"cyberboar.dev/cyberboar/internal/endpoint/httpsclient"
	"cyberboar.dev/cyberboar/internal/endpoint/strictjson"
	"cyberboar.dev/cyberboar/pkg/audit"
)

// maxBatchEvents and maxBatchBytes bound a batch below the console's limits
// of 1000 events and 4 MiB.
const (
	maxBatchEvents = 1000
	maxBatchBytes  = 3 << 20
)

// Options configure one run.
type Options struct {
	AuditPath string // the hook's audit log
	Sink      string // the console's events URL, checked with httpsclient.CheckURL
	StateDir  string // endpoint ID and file offsets
	Hostname  string
	Version   string
	// Client sends the batches. It is the enrolled endpoint's client
	// (enroll.Endpoint.Client), which signs every request and returns an
	// error for an answer the console didn't sign.
	Client *http.Client
	// Now is the clock a Retry-After date is read against
	// If nil, time.Now is used.
	Now func() time.Time
}

// Result counts what one run did.
type Result struct {
	Sent    int // events the console accepted
	Skipped int // lines that aren't valid audit events and were passed over
	Batches int // requests the console accepted, including an empty heartbeat
	// Restarted is true when the log had been truncated or replaced since
	// the last run, so this run shipped it from its start. Lines the old log
	// got after the last run, if there were any, were not shipped, since the
	// old log is out of reach.
	Restarted bool
}

// ErrBusy means another ship run holds the lock.
var ErrBusy = errors.New("another ship run is in progress")

// Once ships everything new in the audit log, then returns. When there was
// nothing to send it sends an empty batch, so the console's fleet view knows
// the endpoint is alive.
func Once(ctx context.Context, o Options) (Result, error) {
	var res Result
	if err := httpsclient.CheckURL(o.Sink); err != nil {
		return res, err
	}
	if o.Client == nil {
		return res, errors.New("no client: events are only sent as an enrolled endpoint")
	}
	auditPath, err := filepath.Abs(o.AuditPath)
	if err != nil {
		return res, err
	}
	id, err := enroll.EndpointID(o.StateDir)
	if err != nil {
		return res, err
	}
	unlock, err := lock(o.StateDir)
	if err != nil {
		return res, err
	}
	defer unlock()
	s := shipper{client: o.Client, sink: o.Sink, now: o.Now, auditPath: auditPath, offPath: offsetFile(o.StateDir, auditPath),
		ep: audit.Endpoint{ID: id, Hostname: o.Hostname, Version: o.Version}}
	if s.now == nil {
		s.now = time.Now
	}
	st, err := loadOffset(s.offPath, auditPath)
	if err != nil {
		return res, err
	}
	off := st.Offset

	f, err := os.Open(auditPath)
	if errors.Is(err, os.ErrNotExist) {
		f = nil // nothing logged yet
	} else if err != nil {
		return res, err
	}
	if f != nil {
		defer f.Close()
		fi, err := f.Stat()
		if err != nil {
			return res, err
		}
		same, err := sameLog(f, fi.Size(), st)
		if err != nil {
			return res, err
		}
		if !same {
			// The log was truncated or replaced (rotated). Its new contents
			// are shipped from the start, and the restart is saved at once,
			// so it is reported only once even when this run sends nothing
			off, res.Restarted = 0, true
			if err := saveOffset(s.offPath, auditPath, f, 0); err != nil {
				return res, err
			}
		}
		s.f, s.r = f, bufio.NewReaderSize(f, audit.MaxLineBytes+1)
		for {
			next, sent, err := s.batch(ctx, off, &res)
			if err != nil {
				return res, err
			}
			off = next
			if !sent {
				break
			}
		}
	}
	if res.Batches == 0 {
		if err := s.send(ctx, audit.Batch{Endpoint: s.ep, Events: []json.RawMessage{}}); err != nil {
			return res, err
		}
		res.Batches++
	}
	return res, nil
}

// shipper holds what the batches of one run share.
type shipper struct {
	client    *http.Client
	sink      string
	now       func() time.Time
	ep        audit.Endpoint
	auditPath string
	offPath   string
	f         *os.File      // the audit log
	r         *bufio.Reader // reads f
}

// batch reads the complete lines that follow off in the log, up to one
// batch, sends their events and saves the offset after the last line read.
// It adds what it did to res and returns the new offset. sent is false when
// there was no event left to send.
func (s *shipper) batch(ctx context.Context, off int64, res *Result) (next int64, sent bool, err error) {
	// The reader starts every batch at off with nothing buffered. A read
	// that stops at a line the hook is still writing has already taken that
	// line's first part from the file, but off stays at the line's start. If
	// the next batch read on from there, it would take the rest of the line
	// for a line of its own, pass over it as invalid and lose the event
	if _, err := s.f.Seek(off, io.SeekStart); err != nil {
		return off, false, err
	}
	s.r.Reset(s.f)
	events, next, skipped, err := readBatch(s.r, off)
	res.Skipped += skipped
	if err != nil {
		return off, false, err
	}
	if len(events) > 0 {
		if err := s.send(ctx, audit.Batch{Endpoint: s.ep, Events: events}); err != nil {
			return off, false, err
		}
		res.Sent += len(events)
		res.Batches++
	}
	if next != off {
		if err := saveOffset(s.offPath, s.auditPath, s.f, next); err != nil {
			return off, false, err
		}
	}
	return next, len(events) > 0, nil
}

// readBatch reads complete lines from r, which starts at off, until a batch
// is full or the file ends. It returns the offset after the last complete
// line. A last line without its newline is still being written, so it is not
// counted in that offset, although r may have read part of it.
func readBatch(r *bufio.Reader, off int64) (events []json.RawMessage, next int64, skipped int, err error) {
	next = off
	size := 0
	for len(events) < maxBatchEvents && size < maxBatchBytes {
		line, err := r.ReadSlice('\n')
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			// The line is longer than any valid line, so skip to its end
			n, done, derr := discardLine(r)
			if derr != nil {
				return events, next, skipped, derr
			}
			if !done {
				return events, next, skipped, nil // unterminated, so maybe still being written
			}
			next += int64(len(line)) + n
			skipped++
			continue
		case errors.Is(err, io.EOF):
			return events, next, skipped, nil // no complete line left
		case err != nil:
			return events, next, skipped, err
		}
		next += int64(len(line))
		body := bytes.TrimRight(line, "\r\n")
		if len(bytes.TrimSpace(body)) == 0 {
			continue
		}
		if _, perr := audit.ParseLine(body); perr != nil {
			skipped++ // the console would reject the whole batch for it
			continue
		}
		events = append(events, json.RawMessage(bytes.Clone(body)))
		size += len(body) + 1
	}
	return events, next, skipped, nil
}

// discardLine consumes the rest of an overlong line. done is false when the
// file ended before its newline.
func discardLine(r *bufio.Reader) (n int64, done bool, err error) {
	for {
		chunk, err := r.ReadSlice('\n')
		n += int64(len(chunk))
		switch {
		case err == nil:
			return n, true, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			return n, false, nil
		default:
			return n, false, err
		}
	}
}

// send posts one batch to the sink. Only 202 Accepted counts as delivered.
// A Retry-After on 503 or 429 is kept in the error for RetryAfter.
func (s *shipper) send(ctx context.Context, b audit.Batch) error {
	body, err := json.Marshal(b)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.sink, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return fmt.Errorf("sending to %s: timed out", s.sink)
		}
		return fmt.Errorf("sending to %s: %v", s.sink, err)
	}
	defer resp.Body.Close()
	msg, err := io.ReadAll(io.LimitReader(resp.Body, 513))
	if err != nil {
		return fmt.Errorf("reading the console's acknowledgment: %w", err)
	}
	if resp.StatusCode != http.StatusAccepted {
		err := fmt.Errorf("the console answered %s: %q", resp.Status, strings.TrimSpace(string(msg)))
		if resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusTooManyRequests {
			if d := parseRetryAfter(resp.Header.Get("Retry-After"), s.now()); d > 0 {
				return &retryError{err: err, after: d}
			}
		}
		return err
	}
	if len(msg) > 512 {
		return errors.New("the console's acknowledgment is larger than 512 bytes")
	}
	var answer struct {
		Accepted *int `json:"accepted"`
	}
	if err := strictjson.Decode(msg, &answer); err != nil {
		return fmt.Errorf("the console's acknowledgment is invalid: %w", err)
	}
	if answer.Accepted == nil || *answer.Accepted != len(b.Events) {
		return fmt.Errorf("the console did not acknowledge all %d events", len(b.Events))
	}
	return nil
}

// MaxRetryAfter bounds how long a console's Retry-After holds shipping back.
// A misconfigured or hostile console must not silence an endpoint for days.
const MaxRetryAfter = time.Hour

// retryError is a refusal that came with a Retry-After.
type retryError struct {
	err   error
	after time.Duration
}

func (e *retryError) Error() string { return e.err.Error() }
func (e *retryError) Unwrap() error { return e.err }

// RetryAfter returns how long the console asked the endpoint to wait before
// sending again, as recorded in an error Once returned. It returns 0 when the
// console didn't say.
func RetryAfter(err error) time.Duration {
	if re, ok := errors.AsType[*retryError](err); ok {
		return re.after
	}
	return 0
}

// parseRetryAfter reads a Retry-After value, seconds or an HTTP date
// (RFC 9110 §10.2.3), bounded by MaxRetryAfter. Anything else is 0.
func parseRetryAfter(v string, now time.Time) time.Duration {
	var d time.Duration
	if secs, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32); err == nil {
		d = time.Duration(secs) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = t.Sub(now)
	}
	return min(max(d, 0), MaxRetryAfter)
}
