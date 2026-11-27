package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const pinnedQueryReplacement = "TestPinnedQueryGenerationReplacement"

func validateNativeQueryReplacement(path string, id identity) error {
	required := []string{pinnedQueryReplacement}
	return validateQueryEventFile(path, required, required, id)
}

func TestNativeQueryReplacementEvidence(t *testing.T) {
	id := identity{Revision: testRevision, BinarySHA256: strings.Repeat("a", 64)}
	path := filepath.Join(t.TempDir(), "query-model-events.jsonl")
	if err := validateNativeQueryReplacement(path, id); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing artifact: %v", err)
	}
	pass := queryEventLine(t, "pass", pinnedQueryReplacement, "")
	identityEvent := queryIdentityEvent(t, pinnedQueryReplacement, id)
	packagePass := queryEventLine(t, "pass", "", "")
	baseline := strings.TrimSuffix(passingQueryEvents(t, pinnedQueryTests, []string{pinnedQueryReplay, pinnedQuery104}, id), packagePass)
	for _, tc := range []struct{ name, events, want string }{
		{"valid", identityEvent + pass, ""},
		{"absent", "", "reported 0 passes"},
		{"skipped", queryEventLine(t, "skip", pinnedQueryReplacement, ""), "reported skip"},
		{"duplicate pass", identityEvent + pass + pass, "reported 2 passes"},
		{"missing identity", pass, "reported 0 candidate identities"},
		{"duplicate identity", identityEvent + identityEvent + pass, "reported 2 candidate identities"},
		{"wrong revision", strings.Replace(identityEvent, id.Revision, strings.Repeat("b", 40), 1) + pass, "identity does not match"},
		{"wrong digest", strings.Replace(identityEvent, id.BinarySHA256, strings.Repeat("b", 64), 1) + pass, "identity does not match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(baseline+tc.events+packagePass), 0600); err != nil {
				t.Fatal(err)
			}
			err := validateNativeQueryReplacement(path, id)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validation = %v, want %q", err, tc.want)
			}
		})
	}
}
