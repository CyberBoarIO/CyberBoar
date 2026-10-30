package ship

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"cyberboar.dev/cyberboar/internal/endpoint/enroll"
	"cyberboar.dev/cyberboar/internal/endpoint/httpsclient"
	"cyberboar.dev/cyberboar/internal/protocoltest"
	"cyberboar.dev/cyberboar/pkg/audit"
	"cyberboar.dev/cyberboar/pkg/endpointauth"
)

// line uses the Unix epoch so fuzz seeds remain reproducible.
func line(i int, decision string) string {
	timestamp := time.Unix(int64(i%60), 0).UTC().Format(time.RFC3339)
	return fmt.Sprintf(`{"time":%q,"agent":"claude-code","decision":%q,"rule":"r%d","reason":"x","durationMs":1}`, timestamp, decision, i) + "\n"
}

// console records accepted batches; fail makes it answer 503.
type console struct {
	mu      sync.Mutex
	batches []audit.Batch
	fail    bool
	status  int     // with fail: the status to answer (default 503)
	retry   string  // with fail: the Retry-After header, if any
	answer  *string // override the acknowledgment body
	srv     *httptest.Server
}

func newConsole(t *testing.T) *console {
	c := &console{}
	c.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if r.Method != "POST" || r.URL.Path != "/api/v1/events" || r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "bad request", 400)
			return
		}
		if c.fail {
			if c.retry != "" {
				w.Header().Set("Retry-After", c.retry)
			}
			http.Error(w, "store unavailable", cmp.Or(c.status, http.StatusServiceUnavailable))
			return
		}
		var b audit.Batch
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &b); err != nil || b.Events == nil {
			http.Error(w, "bad batch", 400)
			return
		}
		c.batches = append(c.batches, b)
		w.WriteHeader(202)
		if c.answer != nil {
			fmt.Fprint(w, *c.answer)
		} else {
			fmt.Fprintf(w, `{"accepted":%d}`, len(b.Events))
		}
	}))
	c.srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	c.srv.StartTLS()
	t.Cleanup(c.srv.Close)
	return c
}

func (c *console) rules() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, b := range c.batches {
		for _, e := range b.Events {
			var ev audit.Event
			json.Unmarshal(e, &ev)
			out = append(out, ev.Rule)
		}
	}
	return out
}

func setup(t *testing.T) (*console, Options) {
	c := newConsole(t)
	dir := t.TempDir()
	return c, Options{AuditPath: filepath.Join(dir, "audit.jsonl"), Sink: c.srv.URL + "/api/v1/events",
		StateDir: filepath.Join(dir, "state"), Hostname: "dev-laptop", Version: "v1",
		Client: client(t, httpsclient.TLS{CAFile: protocoltest.CAFile(t, c.srv)})}
}

// client is httpsclient.New(tc), which must succeed. Enrolled endpoints wrap it
// to authenticate (package enroll); this package's tests don't need that.
func client(t *testing.T, tc httpsclient.TLS) *http.Client {
	t.Helper()
	c, err := httpsclient.New(tc)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNoClientNoSend(t *testing.T) {
	_, o := setup(t)
	o.Client = nil
	if _, err := Once(context.Background(), o); err == nil {
		t.Fatal("sent without a client")
	}
}

func appendTo(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(s)
	f.Close()
}

func copyTo(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func run(t *testing.T, o Options) Result {
	t.Helper()
	res, err := Once(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestShipsNewLinesOnce(t *testing.T) {
	c, o := setup(t)
	appendTo(t, o.AuditPath, line(1, "deny")+"not json\n"+line(2, "ask")+line(0, "skip")+"\n"+line(3, "allow"))
	res := run(t, o)
	if res.Sent != 3 || res.Skipped != 2 || res.Batches != 1 || strings.Join(c.rules(), " ") != "r1 r2 r3" {
		t.Fatalf("first run: %+v, rules %v", res, c.rules())
	}
	b := c.batches[0]
	if b.Endpoint.Hostname != "dev-laptop" || b.Endpoint.Version != "v1" || !endpointauth.ValidEndpointID(b.Endpoint.ID) {
		t.Errorf("endpoint = %+v", b.Endpoint)
	}

	// Nothing new: a heartbeat with no events
	if res := run(t, o); res.Sent != 0 || res.Batches != 1 || len(c.batches[1].Events) != 0 {
		t.Fatalf("second run: %+v", res)
	}
	if c.batches[1].Endpoint.ID != b.Endpoint.ID {
		t.Error("the endpoint ID changed between runs")
	}

	// A partial last line waits until it is complete
	full := line(4, "deny")
	appendTo(t, o.AuditPath, full[:20])
	if res := run(t, o); res.Sent != 0 {
		t.Fatalf("a partial line was sent: %+v", res)
	}
	appendTo(t, o.AuditPath, full[20:])
	if res := run(t, o); res.Sent != 1 || c.rules()[3] != "r4" {
		t.Fatalf("completed line: %+v %v", res, c.rules())
	}
}

func TestFailedSendIsRetried(t *testing.T) {
	c, o := setup(t)
	appendTo(t, o.AuditPath, line(1, "deny"))
	c.fail = true
	if _, err := Once(context.Background(), o); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("err = %v", err)
	}
	c.fail = false
	if res := run(t, o); res.Sent != 1 || strings.Join(c.rules(), " ") != "r1" {
		t.Fatalf("retry: %+v %v", res, c.rules())
	}
}

func TestInvalidAcknowledgmentKeepsEvents(t *testing.T) {
	for name, answer := range map[string]string{
		"empty":       "",
		"missing":     `{}`,
		"null":        `{"accepted":null}`,
		"partial":     `{"accepted":0}`,
		"too many":    `{"accepted":2}`,
		"negative":    `{"accepted":-1}`,
		"fraction":    `{"accepted":1.0}`,
		"case alias":  `{"Accepted":1}`,
		"duplicate":   `{"accepted":0,"accepted":1}`,
		"extra value": `{"accepted":1} {}`,
		"unknown":     `{"accepted":1,"ignored":true}`,
		"oversized":   `{"accepted":1}` + strings.Repeat(" ", 512),
	} {
		t.Run(name, func(t *testing.T) {
			c, o := setup(t)
			appendTo(t, o.AuditPath, line(1, "deny"))
			c.answer = &answer
			res, err := Once(context.Background(), o)
			if err == nil || res.Sent != 0 || res.Batches != 0 {
				t.Fatalf("invalid acknowledgment advanced shipping: %+v, %v", res, err)
			}
			c.answer = nil
			if res := run(t, o); res.Sent != 1 {
				t.Fatalf("event was not retried: %+v", res)
			}
		})
	}
}

func TestTruncatedLogStartsOver(t *testing.T) {
	c, o := setup(t)
	appendTo(t, o.AuditPath, line(1, "deny")+line(2, "deny"))
	run(t, o)
	os.WriteFile(o.AuditPath, []byte(line(3, "deny")), 0o600)
	run(t, o)
	if got := strings.Join(c.rules(), " "); got != "r1 r2 r3" {
		t.Errorf("rules = %s", got)
	}
}

// A rotated log that has already grown past the saved offset is still new:
// its first lines must be sent, not skipped.
func TestReplacedLogStartsOver(t *testing.T) {
	c, o := setup(t)
	appendTo(t, o.AuditPath, line(1, "deny"))
	run(t, o)
	if err := os.Rename(o.AuditPath, o.AuditPath+".1"); err != nil {
		t.Fatal(err)
	}
	appendTo(t, o.AuditPath, line(2, "deny")+line(3, "deny"))
	run(t, o)
	if got := strings.Join(c.rules(), " "); got != "r1 r2 r3" {
		t.Errorf("rules = %s", got)
	}
}

// stats returns the totals of the last batch the console accepted.
func (c *console) stats() audit.Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.batches) == 0 || c.batches[len(c.batches)-1].Stats == nil {
		return audit.Stats{LogsLost: -1}
	}
	return *c.batches[len(c.batches)-1].Stats
}

// A run that finds the log rotated ships the rest of the old log first, found
// next to the new one by how it starts. It reports the rotation once, even
// when the new log has nothing to send yet.
func TestRotatedLogIsFinished(t *testing.T) {
	c, o := setup(t)
	appendTo(t, o.AuditPath, line(1, "deny"))
	if res := run(t, o); res.Restarted {
		t.Errorf("first run: %+v", res)
	}
	appendTo(t, o.AuditPath, line(2, "deny")) // written after the run, then rotated away
	if err := os.Rename(o.AuditPath, o.AuditPath+".1"); err != nil {
		t.Fatal(err)
	}
	appendTo(t, o.AuditPath+".2", line(9, "deny")) // an older rotation, which doesn't start as the log did
	appendTo(t, o.AuditPath, "")
	if res := run(t, o); !res.Restarted || res.Sent != 1 || res.OldLog != o.AuditPath+".1" {
		t.Errorf("run after the rotation: %+v", res)
	}
	if res := run(t, o); res.Restarted {
		t.Errorf("the same rotation was reported twice: %+v", res)
	}
	appendTo(t, o.AuditPath, line(3, "deny"))
	if res := run(t, o); res.Restarted || res.Sent != 1 {
		t.Errorf("first event of the new log: %+v", res)
	}
	if got := strings.Join(c.rules(), " "); got != "r1 r2 r3" {
		t.Errorf("rules = %s", got)
	}
	if s := c.stats(); s != (audit.Stats{}) {
		t.Errorf("stats = %+v, want none lost", s)
	}

	// copytruncate leaves a copy that starts as the log did
	appendTo(t, o.AuditPath, line(4, "deny"))
	copyTo(t, o.AuditPath, o.AuditPath+".3")
	if err := os.Truncate(o.AuditPath, 0); err != nil {
		t.Fatal(err)
	}
	if res := run(t, o); !res.Restarted || res.OldLog != o.AuditPath+".3" {
		t.Errorf("run after truncation: %+v", res)
	}
	if got := strings.Join(c.rules(), " "); got != "r1 r2 r3 r4" {
		t.Errorf("rules = %s", got)
	}
}

// When the old log is gone, the run reports it, and the console learns it
// from the totals in every batch, heartbeats included. A rotation is counted
// once, and a run that fails to send doesn't count it again.
func TestLostLogIsCounted(t *testing.T) {
	c, o := setup(t)
	appendTo(t, o.AuditPath, line(1, "deny"))
	run(t, o)
	appendTo(t, o.AuditPath, line(2, "deny")) // never sent: the log is deleted
	if err := os.Remove(o.AuditPath); err != nil {
		t.Fatal(err)
	}
	appendTo(t, o.AuditPath, "")
	c.fail = true
	if _, err := Once(context.Background(), o); err == nil {
		t.Fatal("the failing console accepted the heartbeat")
	}
	c.fail = false
	if res := run(t, o); res.Restarted || res.Batches != 1 {
		t.Errorf("the rotation was reported twice: %+v", res)
	}
	if s := c.stats(); s.LogsLost != 1 {
		t.Errorf("heartbeat stats = %+v, want 1 log lost", s)
	}
	// Truncating in place without a copy loses the log too
	appendTo(t, o.AuditPath, line(3, "deny")+"not an event\n")
	run(t, o)
	if err := os.Truncate(o.AuditPath, 0); err != nil {
		t.Fatal(err)
	}
	appendTo(t, o.AuditPath, line(4, "deny"))
	if res := run(t, o); !res.Restarted || res.OldLog != "" {
		t.Errorf("run after truncation: %+v", res)
	}
	if s := c.stats(); s != (audit.Stats{LogsLost: 2, LinesSkipped: 1}) {
		t.Errorf("stats = %+v, want 2 logs lost and 1 line skipped", s)
	}
	if got := strings.Join(c.rules(), " "); got != "r1 r3 r4" {
		t.Errorf("rules = %s", got)
	}
}

// Saved offsets require a complete log fingerprint before any events are sent.
func TestOffsetRequiresHead(t *testing.T) {
	for _, tc := range []struct {
		name, head string
		omit       bool
	}{
		{"missing", "", true},
		{"empty", "", false},
		{"short", strings.Repeat("a", 63), false},
		{"invalid hex", strings.Repeat("g", 64), false},
		{"uppercase", strings.Repeat("A", 64), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, o := setup(t)
			appendTo(t, o.AuditPath, line(1, "deny")+line(2, "deny"))
			abs, _ := filepath.Abs(o.AuditPath)
			os.MkdirAll(o.StateDir, 0o700)
			state := map[string]any{"path": abs, "offset": int64(len(line(1, "deny")))}
			if !tc.omit {
				state["head"] = tc.head
			}
			data, _ := json.Marshal(state)
			path := offsetFile(o.StateDir, abs)
			os.WriteFile(path, data, 0o600)
			if _, err := Once(context.Background(), o); err == nil {
				t.Fatal("accepted a saved offset without a valid log fingerprint")
			}
			if len(c.batches) != 0 {
				t.Error("sent events with an invalid saved offset")
			}
			if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, data) {
				t.Errorf("changed rejected offset state: %v", err)
			}
		})
	}
}

func TestOverlongLineIsSkipped(t *testing.T) {
	c, o := setup(t)
	appendTo(t, o.AuditPath, line(1, "deny")+`{"reason":"`+strings.Repeat("x", 3*audit.MaxLineBytes)+`"}`+"\n"+line(2, "deny"))
	res := run(t, o)
	if res.Sent != 2 || res.Skipped != 1 || strings.Join(c.rules(), " ") != "r1 r2" {
		t.Fatalf("%+v %v", res, c.rules())
	}
}

func TestUnterminatedOverlongLineWaits(t *testing.T) {
	c, o := setup(t)
	appendTo(t, o.AuditPath, line(1, "deny")+strings.Repeat("x", 2*audit.MaxLineBytes))
	if res := run(t, o); res.Sent != 1 || res.Skipped != 0 {
		t.Fatalf("%+v", res)
	}
	appendTo(t, o.AuditPath, "\n"+line(2, "deny"))
	if res := run(t, o); res.Sent != 1 || res.Skipped != 1 || strings.Join(c.rules(), " ") != "r1 r2" {
		t.Fatalf("%+v %v", res, c.rules())
	}
}

// The hook can still be writing the last line when ship reads it. When the
// write completes while the batch before it is being sent, the next batch
// must read the whole line from its start, not the rest of it as a line of its own.
func TestLineCompletedDuringSendIsShipped(t *testing.T) {
	overlong := `{"reason":"` + strings.Repeat("x", 2*audit.MaxLineBytes) + `"}` + "\n"
	for _, tc := range []struct {
		name    string
		last    string // the line being written
		cut     int    // how much of it is in the file when the run starts
		rules   string
		skipped int
	}{
		{"event", line(2, "deny"), 30, "r1 r2 r3", 0},
		{"overlong line", overlong, 3 * audit.MaxLineBytes / 2, "r1 r3", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, o := setup(t)
			appendTo(t, o.AuditPath, line(1, "deny")+tc.last[:tc.cut])
			var once sync.Once
			inner := c.srv.Config.Handler
			c.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				once.Do(func() { appendTo(t, o.AuditPath, tc.last[tc.cut:]) })
				inner.ServeHTTP(w, r)
			})
			first := run(t, o)
			appendTo(t, o.AuditPath, line(3, "deny"))
			second := run(t, o)
			if got := strings.Join(c.rules(), " "); got != tc.rules {
				t.Errorf("shipped %s, want %s", got, tc.rules)
			}
			if skipped := first.Skipped + second.Skipped; skipped != tc.skipped {
				t.Errorf("skipped %d lines, want %d (runs %+v, %+v)", skipped, tc.skipped, first, second)
			}
		})
	}
}

func TestLargeBacklogIsSplit(t *testing.T) {
	c, o := setup(t)
	var sb strings.Builder
	for i := range maxBatchEvents + 5 {
		sb.WriteString(line(i, "deny"))
	}
	appendTo(t, o.AuditPath, sb.String())
	res := run(t, o)
	if res.Sent != maxBatchEvents+5 || res.Batches != 2 || len(c.batches[0].Events) != maxBatchEvents {
		t.Fatalf("%+v", res)
	}
}

func TestMissingLogSendsHeartbeat(t *testing.T) {
	c, o := setup(t)
	if res := run(t, o); res.Batches != 1 || len(c.batches) != 1 || len(c.batches[0].Events) != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	c, o := setup(t)
	redirect := httptest.NewTLSServer(http.RedirectHandler(c.srv.URL+"/api/v1/events", http.StatusTemporaryRedirect))
	defer redirect.Close()
	o.Sink = redirect.URL + "/api/v1/events"
	appendTo(t, o.AuditPath, line(1, "deny"))
	if _, err := Once(context.Background(), o); err == nil || len(c.batches) != 0 {
		t.Fatalf("redirect followed: err %v, batches %d", err, len(c.batches))
	}
}

// tls12Server accepts anything, but speaks at most TLS 1.2.
func tls12Server(t *testing.T) *httptest.Server {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202) }))
	srv.TLS = &tls.Config{MaxVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// otherCA writes a self-signed CA certificate that has nothing to do with the test servers.
func otherCA(t *testing.T) string {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "unrelated test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "other.pem")
	os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	return path
}

// Nothing is sent without TLS 1.3 to a verified server.
// Every failure keeps the events for the next run.
func TestTransportFailsClosed(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202) }))
	defer plain.Close()
	old := tls12Server(t)
	for name, change := range map[string]func(o *Options, tc *httpsclient.TLS){
		"plain http to loopback": func(o *Options, _ *httpsclient.TLS) { o.Sink = plain.URL + "/api/v1/events" },
		"TLS 1.2 server": func(o *Options, tc *httpsclient.TLS) {
			o.Sink = old.URL + "/api/v1/events"
			*tc = httpsclient.TLS{CAFile: protocoltest.CAFile(t, old)}
		},
		"certificate from another CA": func(_ *Options, tc *httpsclient.TLS) { *tc = httpsclient.TLS{CAFile: otherCA(t)} },
		"no CA, self-signed server":   func(_ *Options, tc *httpsclient.TLS) { *tc = httpsclient.TLS{} },
		"CA file missing":             func(_ *Options, tc *httpsclient.TLS) { *tc = httpsclient.TLS{CAFile: "/nonexistent.pem"} },
		"CA file without PEM":         func(o *Options, tc *httpsclient.TLS) { *tc = httpsclient.TLS{CAFile: o.AuditPath} },
		"CA and skip together":        func(_ *Options, tc *httpsclient.TLS) { tc.SkipVerify = true },
	} {
		c, o := setup(t)
		appendTo(t, o.AuditPath, line(1, "deny"))
		tc := httpsclient.TLS{CAFile: protocoltest.CAFile(t, c.srv)}
		change(&o, &tc)
		var err error
		if o.Client, err = httpsclient.New(tc); err == nil {
			_, err = Once(context.Background(), o)
		}
		if err == nil || len(c.batches) != 0 {
			t.Errorf("%s: shipped (err %v)", name, err)
			continue
		}
		// The event is still there for a run that can verify the console
		c2, o2 := setup(t)
		o2.AuditPath, o2.StateDir = o.AuditPath, o.StateDir
		if res := run(t, o2); res.Sent != 1 || len(c2.batches) != 1 {
			t.Errorf("%s: the event was lost: %+v", name, res)
		}
	}
}

// --insecure-skip-verify still encrypts, and still refuses TLS 1.2.
func TestSkipVerify(t *testing.T) {
	c, o := setup(t)
	appendTo(t, o.AuditPath, line(1, "deny"))
	o.Client = client(t, httpsclient.TLS{SkipVerify: true})
	if res := run(t, o); res.Sent != 1 || len(c.batches) != 1 {
		t.Fatalf("%+v", res)
	}
	o.Sink = tls12Server(t).URL + "/api/v1/events"
	appendTo(t, o.AuditPath, line(2, "deny"))
	if _, err := Once(context.Background(), o); err == nil {
		t.Fatal("TLS 1.2 accepted with SkipVerify")
	}
}

func TestCorruptOffsetStops(t *testing.T) {
	c, o := setup(t)
	appendTo(t, o.AuditPath, line(1, "deny"))
	run(t, o)
	abs, _ := filepath.Abs(o.AuditPath)
	os.WriteFile(offsetFile(o.StateDir, abs), []byte("{"), 0o600)
	if _, err := Once(context.Background(), o); err == nil {
		t.Fatal("a corrupt offset was ignored")
	}
	if len(c.batches) != 1 {
		t.Error("sent after a corrupt offset")
	}
}

func TestConcurrentRunIsRefused(t *testing.T) {
	c, o := setup(t)
	appendTo(t, o.AuditPath, line(1, "deny"))
	if _, err := enroll.EndpointID(o.StateDir); err != nil {
		t.Fatal(err)
	}
	unlock, err := lock(o.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Once(context.Background(), o); !errors.Is(err, ErrBusy) || len(c.batches) != 0 {
		t.Fatalf("second run: %v, %d batches", err, len(c.batches))
	}
	unlock()
	if res := run(t, o); res.Sent != 1 {
		t.Fatalf("after unlock: %+v", res)
	}
}

// A console that is overloaded says when to come back; the endpoint is told,
// within limits. A date is read against the caller's clock, which here is
// years away from the real one.
func TestRetryAfter(t *testing.T) {
	now := time.Now().UTC().AddDate(5, 0, 0).Truncate(time.Second)
	for _, tc := range []struct {
		name   string
		status int
		header string
		min    time.Duration
		max    time.Duration
	}{
		{"seconds", 503, "120", 120 * time.Second, 120 * time.Second},
		{"too many requests", 429, "30", 30 * time.Second, 30 * time.Second},
		{"HTTP date", 503, now.Add(10 * time.Minute).Format(http.TimeFormat), 10 * time.Minute, 10 * time.Minute},
		{"capped", 503, "999999", MaxRetryAfter, MaxRetryAfter},
		{"date in the past", 503, now.Add(-time.Minute).Format(http.TimeFormat), 0, 0},
		{"garbage", 503, "soon", 0, 0},
		{"negative", 503, "-5", 0, 0},
		{"not a retry status", 500, "120", 0, 0},
		{"no header", 503, "", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, o := setup(t)
			o.Now = func() time.Time { return now }
			c.fail, c.status, c.retry = true, tc.status, tc.header
			_, err := Once(context.Background(), o)
			if err == nil {
				t.Fatal("a refused batch counted as sent")
			}
			if d := RetryAfter(err); d < tc.min || d > tc.max {
				t.Errorf("RetryAfter = %s, want between %s and %s", d, tc.min, tc.max)
			}
		})
	}
	if RetryAfter(nil) != 0 || RetryAfter(errors.New("x")) != 0 {
		t.Error("RetryAfter of an error without one is not 0")
	}
}

func TestParseRetryAfterNeverNegative(t *testing.T) {
	now := time.Now().UTC().AddDate(5, 0, 0).Truncate(time.Second)
	if d := parseRetryAfter(now.Add(-time.Hour).Format(http.TimeFormat), now); d != 0 {
		t.Errorf("a date in the past = %s, want 0", d)
	}
}
