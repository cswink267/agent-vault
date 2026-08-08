package backup

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const SnapshotFormat = "agent-vault-snapshot"
const SnapshotVersion = 1

type Manifest struct {
	Format    string `json:"format"`
	Version   int    `json:"version"`
	CreatedAt string `json:"created_at"`
	Source    string `json:"source"`
}

var (
	ErrInvalidFormat  = errors.New("invalid snapshot format")
	ErrInvalidVersion = errors.New("invalid snapshot version")
)

func WriteSnapshotTarGz(w io.Writer, dbPath, unsealKeyPath string, manifest Manifest) error {
	gw := gzip.NewWriter(w)
	tw := tar.NewWriter(gw)

	if err := addFileToTar(tw, "vault.db", dbPath, 0o600); err != nil {
		return err
	}
	if err := addFileToTar(tw, "unseal.key", unsealKeyPath, 0o600); err != nil {
		return err
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if err := addBytesToTar(tw, "manifest.json", manifestBytes, 0o644); err != nil {
		return err
	}

	if err := tw.Close(); err != nil {
		return err
	}
	return gw.Close()
}

func ExtractSnapshotTarGz(r io.Reader, destDir string) (Manifest, error) {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return Manifest{}, err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	var manifest Manifest
	var manifestPath string
	var haveVaultDB, haveUnsealKey, haveManifest bool
	stagingDir, err := os.MkdirTemp("", "agent-vault-snapshot-*")
	if err != nil {
		return Manifest{}, err
	}
	defer os.RemoveAll(stagingDir)

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, err
		}

		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			return Manifest{}, fmt.Errorf("unexpected tar member type for %s", hdr.Name)
		}

		switch hdr.Name {
		case "vault.db":
			if haveVaultDB {
				return Manifest{}, fmt.Errorf("duplicate tar member: %s", hdr.Name)
			}
			haveVaultDB = true
		case "unseal.key":
			if haveUnsealKey {
				return Manifest{}, fmt.Errorf("duplicate tar member: %s", hdr.Name)
			}
			haveUnsealKey = true
		case "manifest.json":
			if haveManifest {
				return Manifest{}, fmt.Errorf("duplicate tar member: %s", hdr.Name)
			}
			haveManifest = true
		default:
			return Manifest{}, fmt.Errorf("unexpected tar member: %s", hdr.Name)
		}

		mode := os.FileMode(0o644)
		if hdr.Name == "vault.db" || hdr.Name == "unseal.key" {
			mode = 0o600
		}

		outPath := filepath.Join(stagingDir, hdr.Name)
		if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
			return Manifest{}, err
		}
		f, err := os.OpenFile(outPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			return Manifest{}, err
		}
		if _, err := io.Copy(f, tr); err != nil {
			f.Close()
			return Manifest{}, err
		}
		if err := f.Close(); err != nil {
			return Manifest{}, err
		}
		if hdr.Name == "manifest.json" {
			manifestPath = outPath
		}
	}

	if !haveVaultDB {
		return Manifest{}, fmt.Errorf("missing vault.db")
	}
	if !haveUnsealKey {
		return Manifest{}, fmt.Errorf("missing unseal.key")
	}
	if !haveManifest || manifestPath == "" {
		return Manifest{}, fmt.Errorf("missing manifest.json")
	}

	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return Manifest{}, err
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return Manifest{}, err
	}
	if manifest.Format != SnapshotFormat {
		return Manifest{}, ErrInvalidFormat
	}
	if manifest.Version != SnapshotVersion {
		return Manifest{}, ErrInvalidVersion
	}
	if err := installSnapshotMembers(stagingDir, destDir, []string{"vault.db", "unseal.key", "manifest.json"}); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func installSnapshotMembers(stagingDir, destDir string, names []string) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}

	type preparedFile struct {
		name      string
		tmpPath   string
		finalPath string
	}
	prepared := make([]preparedFile, 0, len(names))
	cleanupPrepared := func() {
		for _, p := range prepared {
			_ = os.Remove(p.tmpPath)
		}
	}

	for _, name := range names {
		mode := os.FileMode(0o644)
		if name == "vault.db" || name == "unseal.key" {
			mode = 0o600
		}
		tmpPath, err := copySnapshotMemberToTemp(stagingDir, destDir, name, mode)
		if err != nil {
			cleanupPrepared()
			return err
		}
		prepared = append(prepared, preparedFile{
			name:      name,
			tmpPath:   tmpPath,
			finalPath: filepath.Join(destDir, name),
		})
	}

	// All archive data has been validated and copied to destination temp files;
	// final paths are replaced only during this commit step.
	for _, p := range prepared {
		if err := os.Rename(p.tmpPath, p.finalPath); err != nil {
			cleanupPrepared()
			return err
		}
	}
	return nil
}

func copySnapshotMemberToTemp(stagingDir, destDir, name string, mode os.FileMode) (string, error) {
	in, err := os.Open(filepath.Join(stagingDir, name))
	if err != nil {
		return "", err
	}
	defer in.Close()

	tmp, err := os.CreateTemp(destDir, "."+name+".tmp-*")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
	}()

	if err := tmp.Chmod(mode); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}
	if _, err := io.Copy(tmp, in); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}
	return tmpPath, nil
}

func addFileToTar(tw *tar.Writer, name, path string, mode os.FileMode) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return addBytesToTar(tw, name, data, mode)
}

func addBytesToTar(tw *tar.Writer, name string, data []byte, mode os.FileMode) error {
	hdr := &tar.Header{
		Name:   name,
		Mode:   int64(mode),
		Size:   int64(len(data)),
		Format: tar.FormatGNU,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}
