package engine

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/internal/policy"
)

func TestShellDirectoryChangesCannotAllowProtectedRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses POSIX engine paths")
	}
	root := t.TempDir()
	private := filepath.Join(root, "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(private, "token.txt"), []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := emptyPolicy(policy.DenyListed)
	p.Spec.Files.Deny = []string{filepath.Join(private, "token.txt")}
	c := mustCompile(t, p)
	for _, command := range []string{
		"shopt -s lastpipe; true | cd private; cat token.txt",
		"case x in x) cd private ;& *) cat token.txt ;; esac",
		"case x in x) cd private ;;& y) true ;; *) cat token.txt ;; esac",
	} {
		t.Run(command, func(t *testing.T) {
			a := Action{Tool: ToolShell, Command: command, Cwd: root, Home: "/home/dev", Workspaces: []string{root}}
			v := Evaluate(context.Background(), c, a)
			if v.Decision == Allow || v.Rule != "files.deny[0]" {
				t.Errorf("protected read: got %s by %s", v.Decision, v.Rule)
			}
		})
	}
}

func TestShellAwkEscapesCannotHideProtectedFile(t *testing.T) {
	p := emptyPolicy(policy.DenyListed)
	p.Spec.Files.Deny = []string{"**/.env"}
	c := mustCompile(t, p)
	for _, command := range []string{
		`awk 'BEGIN {getline line < ".\145nv"; print line}'`,
		`awk 'BEGIN {print "fixture" > "\056env"}'`,
		`awk 'BEGIN {print "fixture" >> ".\145nv"}'`,
	} {
		t.Run(command, func(t *testing.T) {
			a := Action{Tool: ToolShell, Command: command, Cwd: "/work/repo", Home: "/home/dev", Workspaces: []string{"/work/repo"}}
			assertDeny(t, Evaluate(context.Background(), c, a), "files.deny[0]")
		})
	}
}

func TestShellPowerShellOptionsCannotHideInlineCode(t *testing.T) {
	c := mustCompile(t, emptyPolicy(policy.DenyListed))
	for _, command := range []string{
		`pwsh -ExecutionPolicy Bypass -Command 'Write-Output fixture'`,
		`pwsh -OutputFormat Text -Command 'Write-Output fixture'`,
		`pwsh /ExecutionPolicy Bypass /Command 'Write-Output fixture'`,
		`pwsh ' -OutputFormat ' Text ' -Command ' 'Write-Output fixture'`,
		"pwsh \u2013ExecutionPolicy Bypass \u2014Command 'Write-Output fixture'",
		`pwsh -NoProfile -ep Bypass -enc AAA`,
	} {
		t.Run(command, func(t *testing.T) {
			a := Action{Tool: ToolShell, Command: command, Cwd: "/work/repo", Home: "/home/dev", Workspaces: []string{"/work/repo"}}
			assertDeny(t, Evaluate(context.Background(), c, a), RuleDenyInterpreters)
		})
	}
}

// Exceeding a scan limit must block even when the policy asks about secrets
// The audit log must not retain a command that could not be checked fully
func TestShellLiteralLimitsBlockAndRedact(t *testing.T) {
	for name, command := range map[string]string{
		"doubling":   "A=x;" + strings.Repeat("A=$A$A;", 20) + "echo $A",
		"word count": "echo " + strings.Repeat("x ", 4100),
	} {
		t.Run(name, func(t *testing.T) {
			for _, mode := range []policy.SecretsAction{policy.SecretsDeny, policy.SecretsAsk, ""} {
				a := Action{Tool: ToolShell, Command: command, Cwd: "/work/repo", Home: "/home/dev", Workspaces: []string{"/work/repo"}}
				assertDeny(t, Evaluate(context.Background(), mustCompile(t, secretsPolicy(mode)), a), RuleTooComplex)
			}
			if got := Redact(context.Background(), command, true); got != "[REDACTED:unchecked]" {
				t.Errorf("unchecked command was not redacted: %d bytes", len(got))
			}
		})
	}
	command := "A=gh; B=example; echo $A$B"
	if got := Redact(context.Background(), command, true); got != command {
		t.Errorf("small harmless command changed: %q", got)
	}
}
