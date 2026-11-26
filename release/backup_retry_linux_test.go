package backup

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

const retryChildTarget = "BOG_RELEASE_BACKUP_RETRY_TARGET"

type interruptedExport struct{ Snapshot }

func (s interruptedExport) OpenWAL() (WALReader, error) {
	// Export has written the staged checkpoint by the time it opens the WAL.
	ready := os.NewFile(3, "backup stage ready")
	if _, err := ready.Write([]byte{'R'}); err != nil {
		return nil, err
	}
	if err := ready.Close(); err != nil {
		return nil, err
	}
	time.Sleep(time.Minute)
	return nil, errors.New("publisher was not interrupted")
}

func TestReleaseBackupExportRetry(t *testing.T) {
	input := newFixture(t)
	if target := os.Getenv(retryChildTarget); target != "" {
		must(t, Export(t.Context(), interruptedExport{input}, target))
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	root := t.TempDir()
	target := filepath.Join(root, "image")
	foreign := filepath.Join(root, ".bog-backup-unrelated")
	must(t, os.WriteFile(foreign, []byte("keep"), 0600))
	for range 3 {
		interruptBackupExport(t, ctx, target)
		if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("interrupted export installed its destination: %v", err)
		}
	}
	must(t, Export(ctx, input, target))
	got, err := Verify(ctx, target)
	must(t, err)
	if got != input.Point() {
		t.Fatalf("retry published %+v, want %+v", got, input.Point())
	}
	raw, err := os.ReadFile(foreign)
	must(t, err)
	if string(raw) != "keep" {
		t.Fatal("retry modified an unrelated sibling")
	}
	entries, err := os.ReadDir(root)
	must(t, err)
	// A permanent destination lock may remain. A stage is a directory.
	for _, entry := range entries {
		if entry.IsDir() && entry.Name() != filepath.Base(target) {
			t.Fatalf("retry left staging directory %s", entry.Name())
		}
	}
}

func interruptBackupExport(t *testing.T, ctx context.Context, target string) {
	t.Helper()
	reader, writer, err := os.Pipe()
	must(t, err)
	defer reader.Close()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestReleaseBackupExportRetry$")
	cmd.Env = append(os.Environ(), retryChildTarget+"="+target)
	cmd.ExtraFiles = []*os.File{writer}
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	startErr := cmd.Start()
	_ = writer.Close()
	must(t, startErr)
	var ready [1]byte
	_, readErr := io.ReadFull(reader, ready[:])
	killErr := cmd.Process.Kill()
	exitErr := cmd.Wait()
	must(t, readErr)
	must(t, killErr)
	var exited *exec.ExitError
	if ready[0] != 'R' || !errors.As(exitErr, &exited) || exited.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("export did not reach staging and exit by SIGKILL: %q, %v", ready, exitErr)
	}
}
