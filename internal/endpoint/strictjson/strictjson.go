// Package strictjson decodes JSON that an endpoint reads from a file or
// receives from a console and acts on. Anything unexpected is refused rather
// than ignored.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"cyberboar.dev/cyberboar/pkg/audit"
)

// Decode decodes data into v. Fields v has no place for, and anything after
// the one JSON value, duplicate keys and case aliases are errors.
func Decode(data []byte, v any) error {
	if err := audit.CheckKeys(data, v); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("data after the JSON value")
	}
	return nil
}
