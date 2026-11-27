// Copied into the pinned release gate to probe and validate only parity.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
)

func selectedTailAvailable(ctx context.Context, binary, root string) (bool, error) {
	client := &http.Client{
		Transport:     &http.Transport{},
		Timeout:       2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	available := false
	err := serveDirectory(ctx, binary, root, client, nil, func(ctx context.Context, base string) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/_capacity/compaction?action=status&cutoff=0", nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
			available = true
		case http.StatusNotFound:
		default:
			return fmt.Errorf("opted-in loopback compaction status: HTTP %d", resp.StatusCode)
		}
		return nil
	})
	return available, err
}

func TestValidateNativeSelectedTailParity(t *testing.T) {
	path := os.Getenv("BOG_RELEASE_VALIDATE_PARITY")
	if path == "" {
		t.Skip("native parity report path required")
	}
	id, err := readIdentity(os.Getenv("BOG_RELEASE_BINARY"), os.Getenv("BOG_RELEASE_REVISION"), os.Getenv("BOG_RELEASE_FIXTURE"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateFile(path, id, cutoverParityCases, validationOptions{requireCutover: true}); err != nil {
		t.Fatal(err)
	}
}
