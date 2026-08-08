package backup_test

import (
	"reflect"
	"testing"

	"github.com/cswink267/agent-vault/internal/backup"
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

	if _, err := backup.OpenExport("wrong-pass", blob); err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
}
