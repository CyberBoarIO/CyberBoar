package enroll

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"cyberboar.dev/cyberboar/pkg/endpointauth"
)

// transport is the round tripper of the client Client returns. It signs
// requests and checks answers.
type transport struct {
	base    http.RoundTripper
	e       *Endpoint
	console *url.URL
}

// RoundTrip implements http.RoundTripper.
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	u := req.URL
	if u.Scheme != t.console.Scheme || u.Host != t.console.Host || !strings.HasPrefix(u.EscapedPath(), t.console.EscapedPath()+"/") {
		closeBody(req)
		return nil, fmt.Errorf("refusing to send %s: this endpoint is enrolled with %s and talks to nothing else", u.Redacted(), t.e.Console)
	}
	if err := t.e.checkCurrent(); err != nil {
		closeBody(req)
		return nil, err
	}
	var body []byte
	if req.Body != nil && req.Body != http.NoBody {
		var err error
		body, err = io.ReadAll(io.LimitReader(req.Body, maxRequest+1))
		req.Body.Close()
		if err != nil {
			return nil, err
		}
		if len(body) > maxRequest {
			return nil, fmt.Errorf("the request body is larger than %d bytes", maxRequest)
		}
	}
	r := req.Clone(req.Context())
	r.Body, r.ContentLength, r.GetBody = http.NoBody, 0, nil
	if len(body) > 0 {
		r.Body, r.ContentLength = io.NopCloser(bytes.NewReader(body)), int64(len(body))
		r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	}
	signer := &endpointauth.Signer{ID: t.e.EndpointID, Key: t.e.key, Now: t.e.clock}
	if err := signer.Sign(r, body); err != nil {
		return nil, err
	}
	resp, err := t.base.RoundTrip(r)
	if err != nil || resp.StatusCode >= 400 {
		// An error answer may be unsigned, since a proxy can produce one.
		// The caller only reports it.
		return resp, err
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("reading the console's answer: %v", err)
	}
	if len(data) > maxAnswer {
		return nil, fmt.Errorf("the console's answer is larger than %d bytes", maxAnswer)
	}
	if err := endpointauth.VerifyResponse(resp, data, r, t.e.consoleKey, t.e.clock()); err != nil {
		return nil, fmt.Errorf("the answer to %s %s is not the console's: %v", r.Method, u.Redacted(), err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(data))
	resp.ContentLength = int64(len(data))
	return resp, nil
}

func closeBody(req *http.Request) {
	if req.Body != nil {
		req.Body.Close()
	}
}

// answerError returns an error that describes an error answer by its status
// and, when the body has them, the protocol's error code and message.
func answerError(resp *http.Response) error {
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var er endpointauth.ErrorResponse
	if json.Unmarshal(data, &er) == nil && er.Error != "" {
		return fmt.Errorf("the console answered %s: %q: %q", resp.Status, er.Error, er.Message)
	}
	return fmt.Errorf("the console answered %s: %q", resp.Status, strings.TrimSpace(string(data)))
}
