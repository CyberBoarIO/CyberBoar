package httpsclient_test

import (
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/endpoint/httpsclient"
)

func TestInvalidURLErrorsDoNotEchoCredentials(t *testing.T) {
	for _, raw := range []string{
		"https://private-user:private-password@console.example/x",
		"https://private-user:private-password@console.example/%zz",
		"https://private-user:private-password@console.example:invalid/x",
	} {
		err := httpsclient.CheckURL(raw)
		if err == nil || strings.Contains(err.Error(), "private-user") || strings.Contains(err.Error(), "private-password") {
			t.Errorf("credential-bearing URL error: %v", err)
		}
	}
}

func TestCheckURLRequiresHTTPSWithoutCredentials(t *testing.T) {
	for sink, ok := range map[string]bool{
		"https://console.example.com/api/v1/events": true,
		"https://127.0.0.1:8443/api/v1/events":      true,
		"http://127.0.0.1:8080/api/v1/events":       false, // no plain http, loopback included
		"http://[::1]:8080/api/v1/events":           false,
		"http://localhost:8080/api/v1/events":       false,
		"http://console.example.com/api/v1/events":  false,
		"https://user:pw@console.example.com/x":     false,
		"ftp://console.example.com/x":               false,
		"/api/v1/events":                            false,
		"https:opaque":                              false,
		"":                                          false,
	} {
		if err := httpsclient.CheckURL(sink); (err == nil) != ok {
			t.Errorf("CheckURL(%q) = %v, want ok %v", sink, err, ok)
		}
	}
}
