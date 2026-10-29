package shell

import "mvdan.cc/sh/v3/syntax"

// The command budget bounds every set to four 64-bit words. Store graph
// rows directly, rather than hashing individual edges or allocating a
// boolean slice for each row of the reachability matrix.
type commandSet [(MaxCommands + 63) / 64]uint64

func (s commandSet) has(id int) bool {
	return s[id/64]&(uint64(1)<<uint(id%64)) != 0
}

func (s *commandSet) add(id int) {
	s[id/64] |= uint64(1) << uint(id%64)
}

func (s *commandSet) merge(other commandSet) {
	for i := range s {
		s[i] |= other[i]
	}
}

type commandSpan struct{ start, end int }

// indexCommands records subtree ranges in a single preorder list of ids.
// The ranges reproduce cmdsIn's old Walk order without rescanning overlapping
// subtrees (notably every left-hand prefix of a long pipeline).
// Only node types queried by linkFile need an entry. Inline-code ASTs have their own
// index; their graph relations are connected separately by transparency.
func indexCommands(f *syntax.File, ids map[*syntax.Stmt]int) (map[syntax.Node]commandSpan, []int) {
	spans := make(map[syntax.Node]commandSpan)
	order := make([]int, 0, len(ids))
	type visit struct {
		node  syntax.Node
		start int
	}
	var stack []visit
	syntax.Walk(f, func(n syntax.Node) bool {
		if n != nil {
			stack = append(stack, visit{n, len(order)})
			if st, ok := n.(*syntax.Stmt); ok {
				if id, ok := ids[st]; ok {
					order = append(order, id)
				}
			}
			return true
		}
		frame := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		switch frame.node.(type) {
		case *syntax.Stmt, syntax.Command, *syntax.CmdSubst, *syntax.ProcSubst:
			spans[frame.node] = commandSpan{frame.start, len(order)}
		}
		return true
	})
	return spans, order
}
