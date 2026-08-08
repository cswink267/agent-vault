package ui

import (
	"io/fs"
	"strings"
	"testing"
)

func TestTemplatesHaveNoInlineScripts(t *testing.T) {
	err := fs.WalkDir(templatesFS, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".html") {
			return nil
		}
		b, readErr := templatesFS.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		body := string(b)
		if strings.Contains(body, "<script>") {
			t.Errorf("%s contains inline <script> which CSP script-src 'self' blocks", path)
		}
		if !strings.Contains(body, `src="/ui/static/app.js"`) && strings.Contains(body, "<body") {
			// layout.html is a partial without its own script tag — skip fragments without body close? all pages should load app.js
			if strings.Contains(body, "</html>") {
				t.Errorf("%s is a full page but does not load /ui/static/app.js", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAppJSAutoBoots(t *testing.T) {
	b, err := staticFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	if !strings.Contains(js, "function boot()") {
		t.Fatal("app.js missing boot()")
	}
	if strings.Count(js, "function boot()") != 1 {
		t.Fatalf("app.js should define boot() once, found %d", strings.Count(js, "function boot()"))
	}
	if !strings.Contains(js, "DOMContentLoaded") {
		t.Fatal("app.js should register DOMContentLoaded for boot")
	}
}
