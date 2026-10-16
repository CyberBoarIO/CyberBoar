package bundle_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cyberboar.dev/cyberboar/pkg/brand"
	"cyberboar.dev/cyberboar/pkg/bundle"
)

func readBaseline(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("../../examples/baseline.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func policyNamed(t *testing.T, name string) []byte {
	return bytes.Replace(readBaseline(t), []byte("name: baseline"), []byte("name: "+name), 1)
}

func write(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "baseline.yaml", readBaseline(t))
	write(t, dir, "strict.yml", policyNamed(t, "strict"))
	write(t, dir, "broken.yaml", []byte("apiVersion: nope\n"))
	write(t, dir, "dup-a.yaml", policyNamed(t, "dup"))
	write(t, dir, "dup-b.yaml", policyNamed(t, "dup"))
	write(t, dir, "badname.yaml", policyNamed(t, strings.Repeat("n", 64)))
	write(t, dir, "latin1.yaml", append(policyNamed(t, "latin"), []byte("# caf\xe9\n")...))
	write(t, dir, "README.md", []byte("not a policy"))
	write(t, dir, ".hidden.yaml", policyNamed(t, "hidden"))
	os.Mkdir(filepath.Join(dir, "sub.yaml"), 0o700)
	secret := filepath.Join(t.TempDir(), "secret.yaml")
	write(t, filepath.Dir(secret), "secret.yaml", policyNamed(t, "outside"))
	must(t, os.Symlink(secret, filepath.Join(dir, "outside.yaml")))
	must(t, os.Symlink("../"+filepath.Base(dir)+"/../"+filepath.Base(dir)+"/nowhere", filepath.Join(dir, "dangling.yaml")))
	// A ConfigMap volume: name.yaml -> ..data/name.yaml, ..data -> ..revision/
	must(t, os.Mkdir(filepath.Join(dir, "..revision"), 0o700))
	write(t, filepath.Join(dir, "..revision"), "cm.yaml", policyNamed(t, "configmap"))
	must(t, os.Symlink("..revision", filepath.Join(dir, "..data")))
	must(t, os.Symlink("..data/cm.yaml", filepath.Join(dir, "cm.yaml")))

	set, err := bundle.LoadDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	status := map[string]string{}
	for _, s := range set.Sources {
		files = append(files, s.File)
		status[s.File] = "ok"
		if s.Err != nil {
			status[s.File] = s.Err.Error()
		}
	}
	if got := strings.Join(files, " "); got != "badname.yaml baseline.yaml broken.yaml cm.yaml dangling.yaml dup-a.yaml dup-b.yaml latin1.yaml outside.yaml strict.yml" {
		t.Errorf("files = %s (hidden files, directories and non-YAML are skipped)", got)
	}
	for file, want := range map[string]string{
		"baseline.yaml": "ok", "strict.yml": "ok", "broken.yaml": "apiVersion", "dup-a.yaml": "neither is served",
		"dup-b.yaml": "neither is served", "badname.yaml": "metadata.name", "latin1.yaml": "UTF-8",
		"cm.yaml": "ok", "outside.yaml": "inside the policy directory", "dangling.yaml": "inside the policy directory",
	} {
		if !strings.Contains(status[file], want) {
			t.Errorf("%s: status %q, want %q", file, status[file], want)
		}
	}
	var names []string
	for _, b := range set.Bundles() {
		names = append(names, b.Name)
	}
	if strings.Join(names, " ") != "baseline configmap strict" {
		t.Errorf("bundles = %v", names)
	}
	if _, ok := set.Bundle("dup"); ok {
		t.Error("a duplicated name is served")
	}
}

func TestSymlinkedDirectory(t *testing.T) {
	real := t.TempDir()
	write(t, real, "baseline.yaml", readBaseline(t))
	link := filepath.Join(t.TempDir(), "policies")
	must(t, os.Symlink(real, link))
	set, err := bundle.LoadDir(link, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := set.Bundle("baseline"); !ok {
		t.Error("a symlinked policy directory (git-sync) serves nothing")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestBundleEnvelope(t *testing.T) {
	dir := t.TempDir()
	data := readBaseline(t)
	write(t, dir, "baseline.yaml", data)
	set, err := bundle.LoadDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, ok := set.Bundle("baseline")
	if !ok {
		t.Fatal("no baseline bundle")
	}
	var env bundle.Envelope
	dec := json.NewDecoder(bytes.NewReader(b.Body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		t.Fatal(err)
	}
	if env.APIVersion != brand.APIVersion || env.Kind != bundle.Kind || env.Name != "baseline" ||
		env.Policy != string(data) || env.PolicySHA256 != b.PolicySHA256 || len(b.PolicySHA256) != 64 {
		t.Errorf("envelope = %+v", env)
	}
	if !strings.HasPrefix(b.ETag, `"sha256-`) || !strings.HasSuffix(b.ETag, `"`) {
		t.Errorf("ETag = %s", b.ETag)
	}

	// Same bytes, same bundle: output is diffable and cacheable
	again, _ := bundle.LoadDir(dir, nil)
	b2, _ := again.Bundle("baseline")
	if !bytes.Equal(b.Body, b2.Body) || b.ETag != b2.ETag {
		t.Error("bundle is not deterministic")
	}
	write(t, dir, "baseline.yaml", append(data, []byte("# edited\n")...))
	changed, _ := bundle.LoadDir(dir, nil)
	b3, _ := changed.Bundle("baseline")
	if b3.ETag == b.ETag || b3.PolicySHA256 == b.PolicySHA256 {
		t.Error("an edited policy kept its ETag")
	}
}

func TestLoadDirErrors(t *testing.T) {
	if _, err := bundle.LoadDir(filepath.Join(t.TempDir(), "missing"), nil); err == nil {
		t.Error("a missing directory is an error")
	}
	var nilSet *bundle.Set
	if _, ok := nilSet.Bundle("x"); ok || nilSet.Bundles() != nil {
		t.Error("a nil set serves nothing")
	}
}

func TestLoadDirBound(t *testing.T) {
	dir := t.TempDir()
	for i := range bundle.MaxFiles + 1 {
		write(t, dir, strings.Repeat("a", 1+i/26)+string(rune('a'+i%26))+".yaml", nil)
	}
	if _, err := bundle.LoadDir(dir, nil); err == nil {
		t.Error("too many files is an error")
	}
}

func TestOversizedPolicy(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "big.yaml", append(readBaseline(t), bytes.Repeat([]byte("#\n"), 1<<20)...))
	set, err := bundle.LoadDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if set.Sources[0].Err == nil || len(set.Bundles()) != 0 {
		t.Error("an oversized policy is served")
	}
}

// A signature is held to the policy's rule: a link out of the directory is
// never read, and the policy isn't served
func TestSignatureSymlinks(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.txt")
	write(t, filepath.Dir(outside), "secret.txt", []byte("not for the console"))
	write(t, dir, "leak.yaml", policyNamed(t, "leak"))
	must(t, os.Symlink(outside, filepath.Join(dir, "leak.yaml.sig")))
	must(t, os.Mkdir(filepath.Join(dir, "..revision"), 0o700))
	write(t, filepath.Join(dir, "..revision"), "cm.yaml", policyNamed(t, "configmap"))
	write(t, filepath.Join(dir, "..revision"), "cm.yaml.sig", []byte("unchecked signature\n"))
	must(t, os.Symlink("..revision", filepath.Join(dir, "..data")))
	must(t, os.Symlink("..data/cm.yaml", filepath.Join(dir, "cm.yaml")))
	must(t, os.Symlink("..data/cm.yaml.sig", filepath.Join(dir, "cm.yaml.sig")))

	set, err := bundle.LoadDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range set.Sources {
		switch s.File {
		case "leak.yaml":
			if s.Err == nil || strings.Contains(s.Sig, "console") {
				t.Errorf("leak.yaml: err %v, sig %q", s.Err, s.Sig)
			}
		case "cm.yaml":
			if s.Err != nil || s.Sig != "unchecked signature\n" {
				t.Errorf("cm.yaml: err %v, sig %q", s.Err, s.Sig)
			}
		}
	}
	if _, ok := set.Bundle("leak"); ok {
		t.Error("a policy whose signature links out of the directory is served")
	}
	if b, ok := set.Bundle("configmap"); !ok || strings.Contains(string(b.Body), "console") {
		t.Errorf("configmap bundle: %v", ok)
	}
}
