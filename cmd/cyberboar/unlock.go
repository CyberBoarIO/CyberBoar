package main

import (
	"flag"
	"fmt"
	"io"
	"time"

	"cyberboar.dev/cyberboar/internal/hook/tripwire"
	"cyberboar.dev/cyberboar/pkg/brand"
)

// runUnlock lists sessions the tripwire tracks, or clears one (or all), which
// unlocks them. It is for the user, never the agent, and the hook denies any
// agent access to the state directory.
func runUnlock(h host, fs *flag.FlagSet, args []string, _ io.Reader, stdout, stderr io.Writer) int {
	fs.SetOutput(stderr)
	stateDir := fs.String("state", "", "the hook's state directory (default: $XDG_STATE_HOME/"+brand.Name+")")
	agent := fs.String("agent", "claude-code", "agent of the session: claude-code, codex, copilot-cli, cursor or opencode")
	session := fs.String("session", "", "session ID to unlock (as in the audit log)")
	all := fs.Bool("all", false, "clear every session")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: %s unlock [--state DIR] [--session ID [--agent NAME] | --all]\n  With no --session or --all, lists the sessions the tripwire tracks.\n", brand.Name)
		printFlagDefaults(fs)
	}
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() > 0 || (*all && *session != "") {
		fs.Usage()
		return 2
	}
	if *stateDir == "" {
		dir, err := h.defaultStateDir()
		if err != nil {
			fmt.Fprintf(stderr, "unlock: %v\n", err)
			return 1
		}
		*stateDir = dir
	}
	store := tripwire.Store{Dir: *stateDir}
	switch {
	case *session != "":
		had, err := store.Unlock(*agent, *session)
		if err != nil {
			fmt.Fprintf(stderr, "unlock: %v\n", err)
			return 1
		}
		if !had {
			fmt.Fprintf(stdout, "%s session %s has no tripwire state; nothing to unlock\n", *agent, *session)
			return 0
		}
		fmt.Fprintf(stdout, "cleared %s session %s\n", *agent, *session)
		return 0
	case *all:
		states, err := store.List()
		if err != nil {
			fmt.Fprintf(stderr, "unlock: %v\n", err)
			return 1
		}
		for _, st := range states {
			if _, err := store.Unlock(st.Agent, st.Session); err != nil {
				fmt.Fprintf(stderr, "unlock: %v\n", err)
				return 1
			}
		}
		fmt.Fprintf(stdout, "cleared %d sessions\n", len(states))
		return 0
	}
	states, err := store.List()
	if err != nil {
		fmt.Fprintf(stderr, "unlock: %v\n", err)
		return 1
	}
	if len(states) == 0 {
		fmt.Fprintln(stdout, "no sessions with denied calls")
		return 0
	}
	for _, st := range states {
		status := "counting"
		if st.Locked {
			status = "LOCKED since " + st.LockedAt.Format(time.RFC3339)
		}
		last := ""
		if n := len(st.Rules); n > 0 {
			last = ", last by " + st.Rules[n-1]
		}
		fmt.Fprintf(stdout, "%-11s %s  %d denied%s  %s\n", st.Agent, st.Session, len(st.Denials), last, status)
	}
	return 0
}
