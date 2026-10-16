package strictjson_test

import (
	"testing"

	"cyberboar.dev/cyberboar/internal/endpoint/strictjson"
)

func TestDecodeRejectsUnexpectedInput(t *testing.T) {
	type T struct{ A int }
	for in, ok := range map[string]bool{
		`{"A": 1}`:         true,
		` {"A": 1} `:       true,
		`{"A": 1, "B": 2}`: false,
		`{"A": 1} {}`:      false,
		`{"A": 1}}`:        false,
		`{"A": 1}]`:        false,
		`{"A": 1} x`:       false,
		``:                 false,
	} {
		var v T
		if err := strictjson.Decode([]byte(in), &v); (err == nil) != ok {
			t.Errorf("Decode(%q) = %v, want ok %v", in, err, ok)
		}
	}
}

func TestDecodeRejectsAmbiguousKeys(t *testing.T) {
	type item struct {
		Value int `json:"value"`
	}
	type message struct {
		Accepted int            `json:"accepted"`
		Items    []item         `json:"items"`
		Labels   map[string]int `json:"labels"`
	}
	for _, in := range []string{
		`{"accepted":0,"accepted":1}`,
		`{"accepted":0,"Accepted":1}`,
		`{"Accepted":1}`,
		`{"items":[{"Value":1}]}`,
		`{"items":[{"value":0,"value":1}]}`,
		`{"labels":{"x":0,"X":1}}`,
	} {
		var v message
		if err := strictjson.Decode([]byte(in), &v); err == nil {
			t.Errorf("accepted ambiguous keys: %s", in)
		}
	}
	var v message
	if err := strictjson.Decode([]byte(`{"accepted":1,"items":[{"value":2}],"labels":{"x":3}}`), &v); err != nil {
		t.Fatal(err)
	}
}
