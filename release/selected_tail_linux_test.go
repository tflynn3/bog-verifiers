// Copied into the pinned release gate for native parity and query qualification.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

var (
	errNoLoopbackCompaction = errors.New("candidate has no opted-in loopback compaction")
	errNoWritableSelector   = errors.New("candidate did not publish bog.authority in the first writable tail cycle")
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

func TestTailParityRejectsFIFOMetadata(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "bog.backup"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := readTailParityImage(ctx, dir, "BOGBAK02")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "bog.backup must be a regular file") {
			t.Fatalf("FIFO metadata: expected regular file diagnostic, got %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("FIFO metadata blocked parity: %v", ctx.Err())
	}
}

func TestValidateNativeQueryQualification(t *testing.T) {
	model, handlers := os.Getenv("BOG_RELEASE_QUERY_MODEL_EVENTS"), os.Getenv("BOG_RELEASE_QUERY_HANDLER_EVENTS")
	if model == "" && handlers == "" {
		t.Skip("native query event files required")
	}
	id, err := readIdentity(os.Getenv("BOG_RELEASE_BINARY"), os.Getenv("BOG_RELEASE_REVISION"), os.Getenv("BOG_RELEASE_FIXTURE"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateQueryQualification(model, handlers, id); err != nil {
		t.Fatal(err)
	}
}
