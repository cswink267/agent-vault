package backup_test

import (
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/cswink267/agent-vault/internal/backup"
	"github.com/cswink267/agent-vault/internal/crypto"
)

func TestExportSealOpenRoundTrip(t *testing.T) {
	recs := []backup.ExportRecord{{Name: "k", Type: "api_key", Secret: "sk-test", Tags: []string{"t"}}}
	blob, err := backup.SealExport("backup-pass", recs)
	if err != nil {
		t.Fatal(err)
	}
	out, err := backup.OpenExport("backup-pass", blob)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out, recs) {
		t.Fatalf("got %+v want %+v", out, recs)
	}
	assertExportHeaderParams(t, blob)

	if _, err := backup.OpenExport("wrong-pass", blob); err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
}

func assertExportHeaderParams(t *testing.T, blob []byte) {
	t.Helper()
	if len(blob) < 18 {
		t.Fatalf("export blob too short: %d", len(blob))
	}
	if string(blob[:4]) != backup.ExportMagic {
		t.Fatalf("magic %q want %q", blob[:4], backup.ExportMagic)
	}
	if blob[4] != 1 {
		t.Fatalf("header version %d want 1", blob[4])
	}
	params := crypto.DefaultKDFParams
	if got := binary.BigEndian.Uint32(blob[5:9]); got != params.Time {
		t.Fatalf("argon2 time %d want %d", got, params.Time)
	}
	if got := binary.BigEndian.Uint32(blob[9:13]); got != params.MemoryKiB {
		t.Fatalf("argon2 memory %d want %d", got, params.MemoryKiB)
	}
	if got := blob[13]; got != params.Threads {
		t.Fatalf("argon2 threads %d want %d", got, params.Threads)
	}
}
