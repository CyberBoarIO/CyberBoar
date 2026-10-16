package shell

import "testing"

// Relative files stay uncertain after a construct that may change the parent
// shell's directory, while ordinary pipelines and separate case arms keep it
func TestCwdPipelineAndCaseScope(t *testing.T) {
	for _, tc := range []struct {
		name, src           string
		persistent, certain bool
	}{
		{"ordinary pipeline", "true | cd private; cat token.txt", false, true},
		{"lastpipe", "shopt -s lastpipe; true | cd private; cat token.txt", false, false},
		{"lastpipe builtin", "builtin shopt -s lastpipe; true | cd private; cat token.txt", false, false},
		{"persistent shell", "true | cd private; cat token.txt", true, false},
		{"subshell", "shopt -s lastpipe; (true | cd private); cat token.txt", false, true},
		{"background pipeline", "shopt -s lastpipe; true | cd private & cat token.txt", false, true},
		{"separate arms", "case x in x) cd private ;; *) cat token.txt ;; esac", false, true},
		{"fall through", "case x in x) cd private ;& *) cat token.txt ;; esac", false, false},
		{"resume matching", "case x in x) cd private ;;& y) true ;; *) cat token.txt ;; esac", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			an, err := AnalyzeWith(tc.src, "/home/dev", Options{Cwd: "/work/repo", Persistent: tc.persistent})
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, f := range an.Files {
				if f.Display == "token.txt" {
					found = true
					if f.Certain != tc.certain || tc.certain && f.Path != "/work/repo/token.txt" {
						t.Errorf("token.txt: %+v, want certain=%v", f, tc.certain)
					}
				}
			}
			if !found {
				t.Fatal("missing token.txt reference")
			}
		})
	}
}
