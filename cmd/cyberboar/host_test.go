package main

import (
	"io"
	"runtime"
	"time"
)

// run runs the CLI as main does, on this operating system, with getenv for its environment, at the current time
func run(args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	return runAt(time.Now, args, stdin, stdout, stderr, getenv)
}

// runAt is run with the clock the commands read given by now
func runAt(now func() time.Time, args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	return host{getenv: getenv, goos: runtime.GOOS, now: now}.run(args, stdin, stdout, stderr)
}

// fixedClock is a clock that always reads at
func fixedClock(at time.Time) func() time.Time {
	return func() time.Time { return at }
}
