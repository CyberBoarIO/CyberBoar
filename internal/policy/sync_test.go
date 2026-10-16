package policy

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"cyberboar.dev/cyberboar/pkg/brand"
)

func TestSyncIntervals(t *testing.T) {
	for _, tc := range []struct {
		name, settings, invalid string
		ship, pull              time.Duration
	}{
		{"omitted", "{}", "", 0, 0},
		{"zero", "{shipEvery: 0s, pullEvery: 0s}", "", 0, 0},
		{"minimum", "{shipEvery: 1s, pullEvery: 10s}", "", time.Second, 10 * time.Second},
		{"hours", "{shipEvery: 5s, pullEvery: 4h}", "", 5 * time.Second, 4 * time.Hour},
		{"compound", "{shipEvery: 1m30s, pullEvery: 2h30m}", "", 90 * time.Second, 150 * time.Minute},
		{"ship too short", "{shipEvery: 999ms}", "spec.sync.shipEvery", 0, 0},
		{"pull too short", "{pullEvery: 9s}", "spec.sync.pullEvery", 0, 0},
		{"negative", "{shipEvery: '-1s'}", "spec.sync.shipEvery", 0, 0},
		{"malformed", "{pullEvery: often}", "spec.sync.pullEvery", 0, 0},
		{"overflow", "{pullEvery: 999999999999999999h}", "spec.sync.pullEvery", 0, 0},
		{"empty", "{shipEvery: ''}", "shipEvery", 0, 0},
		{"numeric", "{pullEvery: 60}", "pullEvery", 0, 0},
		{"typo", "{pullEvry: 4h}", "pullEvry", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Load([]byte(fmt.Sprintf("apiVersion: %s\nkind: Policy\nmetadata: {name: baseline}\nspec: {sync: %s}\n", brand.APIVersion, tc.settings)))
			if tc.invalid != "" {
				if err == nil || !strings.Contains(err.Error(), tc.invalid) {
					t.Fatalf("want error naming %s, got %v", tc.invalid, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if p.Spec.Sync.ShipInterval() != tc.ship || p.Spec.Sync.PullInterval() != tc.pull {
				t.Fatalf("intervals = %s, %s; want %s, %s", p.Spec.Sync.ShipInterval(), p.Spec.Sync.PullInterval(), tc.ship, tc.pull)
			}
		})
	}
}
