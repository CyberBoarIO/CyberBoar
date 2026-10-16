package shell

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// Keep the pre-optimization graph algorithm as a test oracle. Transparent
// wrappers are not ordinary edges: adding outer<->inner edges would invent
// feeds relations when the wrapper has no input/output edges of its own
type referenceGraph struct {
	n           int
	edges       map[[2]int]bool
	transparent []transparent
}

func (g *referenceGraph) link(from, to []int) {
	for _, f := range from {
		for _, t := range to {
			if f != t {
				g.edges[[2]int{f, t}] = true
			}
		}
	}
}

func (g *referenceGraph) linkFile(f *syntax.File, ids map[*syntax.Stmt]int) {
	cmdsIn := func(n syntax.Node) []int {
		var out []int
		if n == nil {
			return nil
		}
		syntax.Walk(n, func(x syntax.Node) bool {
			if st, ok := x.(*syntax.Stmt); ok {
				if id, ok := ids[st]; ok {
					out = append(out, id)
				}
			}
			return true
		})
		return out
	}
	substitutions := func(n syntax.Node, targets []int) {
		syntax.Walk(n, func(m syntax.Node) bool {
			switch s := m.(type) {
			case *syntax.CmdSubst:
				g.link(cmdsIn(s), targets)
			case *syntax.ProcSubst:
				if s.Op == syntax.CmdOut {
					g.link(targets, cmdsIn(s))
				} else {
					g.link(cmdsIn(s), targets)
				}
			}
			return true
		})
	}
	syntax.Walk(f, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.BinaryCmd:
			if x.Op == syntax.Pipe || x.Op == syntax.PipeAll {
				g.link(cmdsIn(x.X), cmdsIn(x.Y))
			}
		case *syntax.Stmt:
			if id, ok := ids[x]; ok {
				substitutions(x, []int{id})
			} else if x.Cmd != nil {
				targets := cmdsIn(x.Cmd)
				for _, r := range x.Redirs {
					substitutions(r, targets)
				}
			}
		}
		return true
	})
}

func (g *referenceGraph) closure() [][]bool {
	n := g.n
	m := make([][]bool, n)
	for i := range m {
		m[i] = make([]bool, n)
	}
	for e := range g.edges {
		m[e[0]][e[1]] = true
	}
	for changed := true; changed; {
		changed = false
		for k := 0; k < n; k++ {
			for i := 0; i < n; i++ {
				if !m[i][k] {
					continue
				}
				for j := 0; j < n; j++ {
					if m[k][j] && !m[i][j] {
						m[i][j] = true
					}
				}
			}
		}
		for _, t := range g.transparent {
			for x := 0; x < n; x++ {
				for _, in := range t.inner {
					if m[x][t.outer] && x != in && !m[x][in] {
						m[x][in], changed = true, true
					}
					if m[t.outer][x] && x != in && !m[in][x] {
						m[in][x], changed = true, true
					}
				}
			}
		}
	}
	return m
}

func compareFeeds(t *testing.T, a *analyzer, ref *referenceGraph) {
	t.Helper()
	got := &Analysis{Commands: a.cmds, feeds: a.closure()}
	want := ref.closure()
	for i := range a.cmds {
		for j := range a.cmds {
			if got.Feeds(i, j) != want[i][j] {
				t.Fatalf("feeds(%d,%d)=%v, want %v; commands=%d, edges=%d, transparent=%v",
					i, j, got.Feeds(i, j), want[i][j], ref.n, len(ref.edges), ref.transparent)
			}
		}
	}
}

func TestLinkFileMatchesReference(t *testing.T) {
	for _, src := range []string{
		"true", "a; b", "a | b | c", "a |& b", "a && b || c",
		"a $(b $(c))", "a <(b | c)", "a > >(b | c)",
		"a <(b) > >(c) | d", "{ a; b; } < <(c | d)",
		"(a | b) > >(c)", "if a; then b | c; else d; fi | e",
		"while a; do b | c; done < <(d)", "f() { a | b; }; f | c",
		"a=$(b | c) d=${x:-$(e)} f", "a $(b <(c $(d))) | e",
		"a | # trailing pipeline comment\nb # final comment\n",
		strings.Repeat("a | ", MaxCommands-1) + "b",
	} {
		t.Run(src, func(t *testing.T) {
			f, err := syntax.NewParser().Parse(strings.NewReader(src), "")
			if err != nil {
				t.Fatal(err)
			}
			compareFileFeeds(t, f)
		})
	}
}

func compareFileFeeds(t *testing.T, f *syntax.File) {
	t.Helper()
	ids := map[*syntax.Stmt]int{}
	syntax.Walk(f, func(n syntax.Node) bool {
		if st, ok := n.(*syntax.Stmt); ok {
			if call, ok := st.Cmd.(*syntax.CallExpr); ok && len(call.Args) > 0 {
				ids[st] = len(ids)
			}
		}
		return true
	})
	if len(ids) > MaxCommands {
		t.Skip("over-budget script is denied before constructing a graph")
	}
	for _, reverse := range []bool{false, true} {
		if reverse {
			// Source order is not command-id order when inline code is analyzed recursively
			// The subtree index must not rely on consecutive ids
			for st, id := range ids {
				ids[st] = len(ids) - 1 - id
			}
		}
		a := &analyzer{cmds: make([]Command, len(ids))}
		ref := &referenceGraph{n: len(ids), edges: map[[2]int]bool{}}
		a.linkFile(f, ids)
		ref.linkFile(f, ids)
		compareFeeds(t, a, ref)
	}
}

// CheckFeedGraph exposes the test-only oracle to the external corpus test
// corpustest imports engine, so importing it from an internal shell test
// would create a cycle. No helper or reference algorithm ships in the binary
func CheckFeedGraph(t *testing.T, src string) {
	t.Helper()
	f, err := syntax.NewParser().Parse(strings.NewReader(src), "")
	if err != nil {
		t.Skip("unparseable commands are denied without a graph")
	}
	compareFileFeeds(t, f)
}

func TestClosureMatchesReference(t *testing.T) {
	// Every directed graph on four vertices, including graphs with cycles,
	// with absent, branching, nested and reversed-order transparency
	for _, tr := range [][]transparent{
		nil, {{0, []int{1, 2}}}, {{0, []int{1}}, {1, []int{2, 3}}},
		{{1, []int{2, 3}}, {0, []int{1}}},
	} {
		for mask := 0; mask < 1<<12; mask++ {
			a := &analyzer{cmds: make([]Command, 4), transparent: tr}
			ref := &referenceGraph{n: 4, edges: map[[2]int]bool{}, transparent: tr}
			bit := 0
			for i := 0; i < 4; i++ {
				for j := 0; j < 4; j++ {
					if i == j {
						continue
					}
					if mask&(1<<bit) != 0 {
						a.link([]int{i}, []int{j})
						ref.link([]int{i}, []int{j})
					}
					bit++
				}
			}
			compareFeeds(t, a, ref)
		}
	}
	// Cross bitset word boundaries, including the maximum supported size
	rng := rand.New(rand.NewPCG(1, 2))
	for _, n := range []int{0, 1, 63, 64, 65, 127, 128, 129, 255, MaxCommands} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			a := &analyzer{cmds: make([]Command, n)}
			ref := &referenceGraph{n: n, edges: map[[2]int]bool{}}
			for range n * 2 {
				from, to := rng.IntN(n), rng.IntN(n)
				a.link([]int{from}, []int{to})
				ref.link([]int{from}, []int{to})
			}
			if n > 1 {
				tr := []transparent{{0, []int{n / 2, n - 1}}}
				a.transparent, ref.transparent = tr, tr
			}
			compareFeeds(t, a, ref)
		})
	}
}

func FuzzFeedGraph(f *testing.F) {
	f.Add([]byte{3, 0, 0, 1, 0, 1, 2, 0, 2, 0})
	f.Add([]byte{5, 1, 0, 1, 1, 1, 2, 0, 3, 0, 0, 2, 4})
	for _, src := range []string{
		"a | b | c", "a $(b $(c))", "a <(b) > >(c) | d",
		"{ a; b; } < <(c | d)", "a=$(b | c) d=${x:-$(e)} f",
	} {
		f.Add([]byte(src))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 || len(data) > 512 {
			return
		}
		n := int(data[0]%12) + 1
		a := &analyzer{cmds: make([]Command, n)}
		ref := &referenceGraph{n: n, edges: map[[2]int]bool{}}
		for i := 1; i+2 < len(data); i += 3 {
			from, to := int(data[i+1])%n, int(data[i+2])%n
			if data[i]%2 == 0 {
				a.link([]int{from}, []int{to})
				ref.link([]int{from}, []int{to})
			} else {
				tr := transparent{from, []int{to}}
				a.transparent = append(a.transparent, tr)
				ref.transparent = append(ref.transparent, tr)
			}
		}
		compareFeeds(t, a, ref)
		if file, err := syntax.NewParser().Parse(strings.NewReader(string(data)), ""); err == nil {
			compareFileFeeds(t, file)
		}
	})
}
