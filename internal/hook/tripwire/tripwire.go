// Package tripwire counts denied tool calls per agent session and locks a
// session that reaches the policy's limit (spec.session.tripwire). An agent
// hunting for a way around a rule is stopped instead of trying variant after
// variant. A locked session stays locked until the user starts a new one or
// runs `cyberboar unlock`
//
// State is one small JSON file per session under Dir, changed under an
// exclusive file lock, since an agent can run several tool calls at once.
// Every error is returned, because the hook denies when it can't tell whether
// a session is locked
package tripwire

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"cyberboar.dev/cyberboar/internal/engine"
)

// RuleLocked is the rule of every verdict in a locked session
const RuleLocked = "tripwire.locked"

// maxState bounds a state file. A larger one is corrupt
const maxState = 64 << 10

// State is one session's record
type State struct {
	Agent   string `json:"agent"`
	Session string `json:"session"`
	// Denials are the times of the counted denials, oldest first, at most the
	// limit's worth
	Denials []time.Time `json:"denials,omitempty"`
	// Rules are the rules behind Denials, in the same order
	Rules    []string  `json:"rules,omitempty"`
	Locked   bool      `json:"locked,omitempty"`
	LockedAt time.Time `json:"lockedAt,omitzero"`
}

// Store keeps session state in Dir
type Store struct {
	Dir string
	// Now returns the current time. If nil, time.Now is used
	Now func() time.Time
}

// now returns the current time in UTC, from Now when it is set
func (s Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// sessionsDir returns the directory that holds the state files
func (s Store) sessionsDir() string { return filepath.Join(s.Dir, "sessions") }

// file names a session's state file by a hash, so any session ID is a safe file name
func (s Store) file(agent, session string) string {
	sum := sha256.Sum256([]byte(agent + "\x00" + session))
	return filepath.Join(s.sessionsDir(), hex.EncodeToString(sum[:16])+".json")
}

// agentErrors are the denials for shell that the engine can't check because
// it is unparseable, nested too deeply or too long. An agent hiding what a
// command does writes shell like that, so these count like policy denials
var agentErrors = map[string]bool{engine.RuleUnparseable: true, engine.RuleTooComplex: true, engine.RuleCommandTooLarge: true}

// Counts reports whether a denial with this rule counts towards the limit
// Decisions of the policy count, from its files, commands, MCP, posture,
// secrets and built-in rules, and so do commands too obscure to check
// CyberBoar's own failures and an adapter's limits don't count, because they
// are no sign of an agent probing the rules
func Counts(rule string) bool {
	if agentErrors[rule] {
		return true
	}
	for _, p := range []string{"files.", "commands.", "mcp.", "posture.", engine.RuleSecretsPrefix, "builtin."} {
		if strings.HasPrefix(rule, p) {
			return true
		}
	}
	return false
}

// Check returns the session's state. A session with no state file yet gets an empty state
func (s Store) Check(agent, session string) (State, error) {
	f, err := s.open(agent, session, false)
	if errors.Is(err, os.ErrNotExist) {
		return State{Agent: agent, Session: session}, nil
	}
	if err != nil {
		return State{}, err
	}
	defer f.Close()
	if err := lockShared(f); err != nil {
		return State{}, err
	}
	return read(f, agent, session)
}

// Record counts one denial and locks the session when the denials within
// window reach limit
// A zero window is the whole session
// Record returns the new state
func (s Store) Record(agent, session, rule string, limit int, window time.Duration) (State, error) {
	if limit < 1 {
		return State{}, fmt.Errorf("tripwire limit %d is below 1", limit)
	}
	f, err := s.open(agent, session, true)
	if err != nil {
		return State{}, err
	}
	defer f.Close()
	if err := lockExclusive(f); err != nil {
		return State{}, err
	}
	st, err := read(f, agent, session)
	if err != nil {
		return State{}, err
	}
	now := s.now()
	st.Denials = append(st.Denials, now)
	st.Rules = append(st.Rules, rule)
	if window > 0 {
		keep := 0
		for keep < len(st.Denials) && !st.Denials[keep].After(now.Add(-window)) {
			keep++
		}
		st.Denials, st.Rules = st.Denials[keep:], st.Rules[keep:]
	}
	if n := len(st.Denials); n > limit {
		st.Denials, st.Rules = st.Denials[n-limit:], st.Rules[n-limit:]
	}
	if len(st.Denials) >= limit && !st.Locked {
		st.Locked, st.LockedAt = true, now
	}
	return st, write(f, st)
}

// Unlock removes a session's state. It reports whether there was any
func (s Store) Unlock(agent, session string) (bool, error) {
	err := os.Remove(s.file(agent, session))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// List returns every session with state, locked ones first, then by agent and session
func (s Store) List() ([]State, error) {
	entries, err := os.ReadDir(s.sessionsDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []State
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		f, err := openFile(filepath.Join(s.sessionsDir(), e.Name()), os.O_RDONLY, 0)
		if err != nil {
			return nil, err
		}
		st, err := read(f, "", "")
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %v", e.Name(), err)
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Locked != b.Locked {
			return a.Locked
		}
		if a.Agent != b.Agent {
			return a.Agent < b.Agent
		}
		return a.Session < b.Session
	})
	return out, nil
}

// open opens a session's state file, creating it (and the directory, private to the user) when create is set
// Symlinks are refused
func (s Store) open(agent, session string, create bool) (*os.File, error) {
	flags := os.O_RDWR
	if create {
		if err := os.MkdirAll(s.sessionsDir(), 0o700); err != nil {
			return nil, err
		}
		flags |= os.O_CREATE
	}
	return openFile(s.file(agent, session), flags, 0o600)
}

// read decodes a state file. An empty file is a new session
// If agent is set, the file must belong to that session
func read(f *os.File, agent, session string) (State, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return State{}, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxState+1))
	if err != nil {
		return State{}, err
	}
	if len(data) == 0 {
		return State{Agent: agent, Session: session}, nil
	}
	if len(data) > maxState {
		return State{}, errors.New("tripwire state file is too large")
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return State{}, fmt.Errorf("tripwire state file is corrupt: %v", err)
	}
	if len(st.Denials) != len(st.Rules) {
		return State{}, errors.New("tripwire state file is corrupt: denials and rules differ in length")
	}
	if agent != "" && (st.Agent != agent || st.Session != session) {
		return State{}, errors.New("tripwire state file belongs to another session")
	}
	return st, nil
}

// write replaces the contents of f with st and flushes them to disk, so a
// lock is durable before the hook answers. It writes before it truncates: a
// hook stopped in between leaves the old file's tail after the new state,
// which doesn't parse and so denies, where an emptied file would read as a
// new session
func write(f *os.File, st State) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if _, err := f.WriteAt(data, 0); err != nil {
		return err
	}
	if err := f.Truncate(int64(len(data))); err != nil {
		return err
	}
	return f.Sync()
}
