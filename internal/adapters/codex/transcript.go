package codex

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"cyberboar.dev/cyberboar/internal/adapters"
)

// Codex's PreToolUse input for Bash carries only the command text. The model
// also chose the directory it runs in (workdir), the shell that interprets
// it (shell) and possibly another machine (environment_id), and none of
// these reach the hook. Codex writes the model's function call, with all its
// arguments, to the session transcript before it runs the tool, so the
// adapter reads the call from there. Anything it can't find or match is
// denied, so a format change in Codex blocks commands and never lets them
// through unchecked

// RuleCallNotFound denies a call the transcript can't vouch for.
const RuleCallNotFound = "adapter.callNotFound"

// The call is near the end of the transcript, so only the last
// transcriptTail bytes are read, and a line longer than maxLine is skipped.
const (
	transcriptTail = 8 << 20
	maxLine        = 4 << 20
)

// transcriptWait is how long to wait for the call to reach the transcript
// (Codex persists it before running the tool, but the write may lag).
const transcriptWait = 1500 * time.Millisecond

// execCall holds the arguments exec_command received from the model.
type execCall struct {
	Cmd           string  `json:"cmd"`
	Workdir       *string `json:"workdir"`
	Shell         *string `json:"shell"`
	Login         *bool   `json:"login"`
	Tty           *bool   `json:"tty"`
	EnvironmentID *string `json:"environment_id"`
}

func callError(format string, args ...any) error {
	return &adapters.Error{Rule: RuleCallNotFound, Msg: fmt.Sprintf(format, args...) +
		"; without it the hook can't tell which directory or shell the command runs in, so it is blocked"}
}

// lookupExecCall finds the exec_command call with the hook's tool_use_id,
// or, for a call made from a code-mode script, the script's call running cmd.
func lookupExecCall(in *Input, cmd string) (*execCall, error) {
	if in.TranscriptPath == nil || *in.TranscriptPath == "" {
		return nil, callError("the hook input has no transcript_path")
	}
	path := *in.TranscriptPath
	if !filepath.IsAbs(path) {
		return nil, callError("transcript_path %q is not absolute", path)
	}
	if in.ToolUseID == "" {
		return nil, callError("the hook input has no tool_use_id")
	}
	deadline := time.Now().Add(transcriptWait)
	for {
		call, err := scanTranscript(path, in.ToolUseID, cmd)
		if errors.Is(err, errNotYet) && time.Now().After(deadline) {
			return nil, callError("the call %s is not in the session transcript", in.ToolUseID)
		}
		if err == nil || !errors.Is(err, errNotYet) {
			return call, err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

var errNotYet = errors.New("call not in the transcript yet")

// transcriptLine is a line of Codex's rollout file.
type transcriptLine struct {
	Type    string `json:"type"`
	Payload struct {
		Type          string          `json:"type"`
		Name          string          `json:"name"`
		Namespace     *string         `json:"namespace"`
		Arguments     *string         `json:"arguments"`
		Input         *string         `json:"input"`
		CallID        string          `json:"call_id"`
		EncryptedArgs json.RawMessage `json:"encrypted_function_args"`
	} `json:"payload"`
}

// codeModeID marks tool calls made from a code-mode script.
const codeModeID = "exec-"

// scanTranscript reads the end of the transcript at path and returns the
// exec_command call with ID callID, or for a call made from a code-mode
// script, the script's call that runs cmd. It returns errNotYet while the
// call isn't in the transcript, so that the caller can wait for Codex to write it.
func scanTranscript(path, callID, cmd string) (*execCall, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, callError("the transcript can't be read (%v)", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return nil, callError("the transcript is not a regular file")
	}
	if off := fi.Size() - transcriptTail; off > 0 {
		// The first line after the seek is usually cut short
		// It then fails to decode and is skipped like any other line that isn't an entry
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			return nil, callError("the transcript can't be read (%v)", err)
		}
	}
	r := bufio.NewReaderSize(f, 64<<10)
	needle := []byte(callID)
	var found *transcriptLine
	matches := 0
	codeMode := strings.HasPrefix(callID, codeModeID)
	running := map[string]string{} // code-mode scripts without output yet, by call_id
	var order []string
	for {
		line, err := readLine(r)
		// running holds the scripts started in the part read whose output
		// isn't in the transcript yet. Codex writes a script's output only
		// when the script ends, so the script that made a nested call is
		// among them if it started in that part
		if codeMode && len(line) > 0 && bytes.Contains(line, []byte(`"custom_tool_call`)) {
			var tl transcriptLine
			if json.Unmarshal(line, &tl) == nil && tl.Type == "response_item" {
				switch p := tl.Payload; p.Type {
				case "custom_tool_call":
					if p.Name == "exec" && p.Input != nil {
						running[p.CallID] = *p.Input
						order = append(order, p.CallID)
					}
				case "custom_tool_call_output":
					delete(running, p.CallID)
				}
			}
		}
		if len(line) > 0 && bytes.Contains(line, needle) {
			var tl transcriptLine
			if json.Unmarshal(line, &tl) == nil && tl.Type == "response_item" &&
				tl.Payload.Type == "function_call" && tl.Payload.CallID == callID {
				found = &tl
				matches++
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, callError("the transcript can't be read (%v)", err)
		}
	}
	// A nested call has no function_call entry of its own, so it is read
	// from the script that made it. The hook input doesn't say which script
	// that is, so the call is trusted only while one script is running
	if codeMode && matches == 0 {
		switch len(running) {
		case 0:
			return nil, errNotYet
		case 1:
			for _, id := range order {
				if src, ok := running[id]; ok {
					return callFromScript(src, cmd)
				}
			}
		}
		return nil, callError("%d code-mode scripts are running at once", len(running))
	}
	switch {
	case matches == 0:
		return nil, errNotYet
	case matches > 1:
		return nil, callError("the transcript has %d calls with id %s", matches, callID)
	}
	p := found.Payload
	if p.Name != "exec_command" || p.Namespace != nil && *p.Namespace != "" {
		return nil, callError("the call %s in the transcript is %q, not exec_command", callID, p.Name)
	}
	if p.Arguments == nil || len(p.EncryptedArgs) > 0 && string(p.EncryptedArgs) != "null" {
		return nil, callError("the call's arguments are not readable in the transcript")
	}
	keys, err := objectKeys(*p.Arguments)
	if err != nil {
		return nil, callError("the call's arguments are not a JSON object (%v)", err)
	}
	if err := checkArgKeys(keys); err != nil {
		return nil, err
	}
	var call execCall
	if err := json.Unmarshal([]byte(*p.Arguments), &call); err != nil {
		return nil, callError("the call's arguments are not valid JSON (%v)", err)
	}
	return &call, nil
}

// objectKeys returns the keys of a JSON object in order, repeats included.
func objectKeys(data string) ([]string, error) {
	dec := json.NewDecoder(strings.NewReader(data))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errors.New("no object")
	}
	var keys []string
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		keys = append(keys, t.(string))
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
	}
	return keys, nil
}

// execFields are the JSON names of execCall's fields.
var execFields = func() []string {
	var names []string
	for f := range reflect.TypeFor[execCall]().Fields() {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		names = append(names, name)
	}
	return names
}()

// checkArgKeys refuses arguments whose keys Codex and encoding/json would
// read differently. Codex matches field names exactly and ignores other
// keys. encoding/json also takes a key equal to a field's name under Unicode
// case folding, such as "Workdir" or a key with the Kelvin sign for its k,
// and keeps the last of several. The hook could then see another working
// directory or shell than the one the command runs in
// Audit lines with such keys are rejected for the same reason.
func checkArgKeys(keys []string) error {
	seen := map[string]bool{}
	for _, k := range keys {
		for _, name := range execFields {
			if !strings.EqualFold(k, name) {
				continue
			}
			if k != name || seen[name] {
				return callError("the call's arguments name %q more than once or in another spelling (%q)", name, k)
			}
			seen[name] = true
		}
	}
	return nil
}

// readLine reads one line. A line longer than maxLine comes back empty,
// since the call isn't in one.
func readLine(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	skip := false
	for {
		chunk, err := r.ReadSlice('\n')
		if !skip && len(buf)+len(chunk) <= maxLine {
			buf = append(buf, chunk...)
		} else {
			skip, buf = true, nil
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return bytes.TrimRight(buf, "\r\n"), err
	}
}
