package semver_test

import (
	"testing"

	"cyberboar.dev/cyberboar/internal/semver"
)

func TestValid(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"1.4.2", true},
		{"v1.4.2", true},
		{"0.0.0", true},
		{"1.0.0-rc.2", true},
		{"1.0.0-alpha-1.x.7z.0", true},
		{"1.2.1-SNAPSHOT-a1b2c3d", true},
		{"1.4.2+dirty", true},
		{"1.4.2-rc.1+build.5", true},
		{"123456789012345678901234567890.0.0", true},

		{"", false},
		{"dev", false},
		{"v", false},
		{"1.4", false},
		{"1.4.2.0", false},
		{"01.4.2", false},
		{"1.04.2", false},
		{"1.4.02", false},
		{"1.4.2-", false},
		{"1.4.2-rc..1", false},
		{"1.4.2-rc.01", false},
		{"1.4.2-rc_1", false},
		{"1.4.2+", false},
		{"1.4.2+a+b", false},
		{"vv1.4.2", false},
		{"V1.4.2", false},
		{" 1.4.2", false},
		{"1.4.2 ", false},
		{"-1.4.2", false},
		{"1.4.x", false},
		{"１.4.2", false},
		{">=1.4.2", false},
	} {
		if got := semver.Valid(tc.in); got != tc.want {
			t.Errorf("Valid(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestAtLeastOrder(t *testing.T) {
	// Ascending, from the Semantic Versioning 2.0.0 precedence examples plus
	// numbers longer than any integer type
	order := []string{
		"0.9.9",
		"1.0.0-alpha",
		"1.0.0-alpha.1",
		"1.0.0-alpha.beta",
		"1.0.0-beta",
		"1.0.0-beta.2",
		"1.0.0-beta.11",
		"1.0.0-rc.1",
		"1.0.0",
		"1.0.1",
		"1.2.0",
		"1.10.0",
		"2.0.0",
		"99999999999999999999.0.0",
		"100000000000000000000.0.0",
	}
	for i, a := range order {
		for j, b := range order {
			if got, want := semver.AtLeast(a, b), i >= j; got != want {
				t.Errorf("AtLeast(%q, %q) = %v, want %v", a, b, got, want)
			}
		}
	}
}

func TestAtLeast(t *testing.T) {
	for _, tc := range []struct {
		version, minimum string
		want             bool
	}{
		{"1.4.2", "v1.4.2", true},
		{"v1.4.2", "1.4.2", true},
		{"1.4.2+dirty", "1.4.2", true},
		{"1.4.2", "1.4.3", false},
		// A snapshot of the next patch release is past the last release, and before the next
		{"1.4.3-SNAPSHOT-a1b2c3d", "1.4.2", true},
		{"1.4.3-SNAPSHOT-a1b2c3d", "1.4.3", false},
		// A release candidate comes before its release
		{"1.0.0-rc.1", "1.0.0", false},
		// What can't be placed is never at least anything
		{"dev", "0.0.0", false},
		{"", "0.0.0", false},
		{"(devel)", "0.0.0", false},
		{"1.4.2", "", false},
		{"1.4.2", "1.4", false},
	} {
		if got := semver.AtLeast(tc.version, tc.minimum); got != tc.want {
			t.Errorf("AtLeast(%q, %q) = %v, want %v", tc.version, tc.minimum, got, tc.want)
		}
	}
}

func FuzzAtLeast(f *testing.F) {
	for _, s := range []string{"1.4.2", "v1.4.2", "1.0.0-rc.1", "1.0.0-alpha.beta", "1.2.1-SNAPSHOT-a1b2c3d+dirty", "dev", ""} {
		f.Add(s, "1.0.0")
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		ab, ba := semver.AtLeast(a, b), semver.AtLeast(b, a)
		if !semver.Valid(a) || !semver.Valid(b) {
			if ab || ba {
				t.Fatalf("AtLeast placed a version it can't parse: %q, %q", a, b)
			}
			return
		}
		if !ab && !ba {
			t.Fatalf("%q and %q are unordered", a, b)
		}
		if !semver.AtLeast(a, a) {
			t.Fatalf("%q is not at least itself", a)
		}
	})
}
