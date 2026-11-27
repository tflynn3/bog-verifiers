// This release-only helper prepares and verifies backup images. The candidate
// server owns the writable directories, HTTP appends and checkpoint selection.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"bog/internal/backup"
	"bog/internal/checkpoint"
)

type view struct {
	root, manifest string
	point          backup.RecoveryPoint
	suffix         []byte
}

func (v view) Point() backup.RecoveryPoint          { return v.point }
func (v view) OpenManifest() (io.ReadCloser, error) { return v.OpenSegment(v.manifest) }
func (v view) OpenSegment(name string) (io.ReadCloser, error) {
	return os.Open(filepath.Join(v.root, name))
}
func (v view) OpenSuffix() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(v.suffix)), nil
}

type legacyView struct{ view }

func (v legacyView) Point() backup.Point {
	return backup.Point{Generation: v.point.Generation, CoveredOffset: v.point.CoveredOffset,
		NextOrdinal: v.point.NextOrdinal, CommittedEnd: v.point.CommittedEnd}
}
func (v legacyView) OpenWAL() (backup.WALReader, error) {
	return os.Open(filepath.Join(v.root, "bog.wal"))
}

func run(args []string) error {
	ctx := context.Background()
	switch args[0] {
	case "checkpoint":
		legacy, err := checkpoint.OpenLegacy(args[1])
		if err != nil {
			return err
		}
		_, err = legacy.Publish()
		return errors.Join(err, legacy.Close())
	case "restore":
		return backup.Restore(ctx, args[1], args[2])
	case "export":
		// The driver supplies the exact observed rebased tail file, and the
		// expected first free ordinal computed from acknowledged batches.
		root, manifest, tail, destination := args[1], args[2], args[3], args[4]
		ordinal, err := strconv.ParseUint(args[5], 10, 64)
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(filepath.Join(root, manifest))
		if err != nil {
			return err
		}
		m, generation, err := checkpoint.DecodeManifest(raw)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(filepath.Join(root, tail))
		if err != nil {
			return err
		}
		if m.Version == 1 {
			if m.CoveredOffset > int64(len(data)) {
				return fmt.Errorf("checkpoint exceeds WAL length")
			}
			data = data[m.CoveredOffset:]
		}
		v := view{root, manifest, backup.RecoveryPoint{
			Generation: generation, CoveredOffset: m.CoveredOffset, NextOrdinal: m.NextOrdinal,
			CommittedEnd: m.CoveredOffset + int64(len(data)), CommittedOrdinal: ordinal,
			SuffixSHA256: sha256.Sum256(data),
		}, data}
		if m.Version == 1 {
			err = backup.Export(ctx, legacyView{v}, destination)
		} else {
			err = backup.ExportRecoveryView(ctx, v, destination, 65536)
		}
		if err != nil {
			return err
		}
		r, err := backup.OpenRestored(ctx, destination)
		if err != nil {
			return err
		}
		if r.RecoveryPoint() != v.point {
			err = fmt.Errorf("verified backup point differs from observed recovery point")
		}
		return errors.Join(err, r.Close())
	default:
		return fmt.Errorf("unknown fixture operation %q", args[0])
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
