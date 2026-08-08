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

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, err
		}

		switch hdr.Name {
		case "vault.db":
			haveVaultDB = true
		case "unseal.key":
			haveUnsealKey = true
		case "manifest.json":
			haveManifest = true
		default:
			return Manifest{}, fmt.Errorf("unexpected tar member: %s", hdr.Name)
		}

		mode := hdr.FileInfo().Mode().Perm()
		if hdr.Name == "unseal.key" {
			mode = 0o600
		}

		outPath := filepath.Join(destDir, hdr.Name)
		if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
			return Manifest{}, err
		}
		f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
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
	return manifest, nil
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
		Name:    name,
		Mode:    int64(mode),
		Size:    int64(len(data)),
		Format:  tar.FormatGNU,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}
