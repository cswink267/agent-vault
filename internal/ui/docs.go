package ui

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"path"
	"regexp"
	"strings"

	"github.com/cswink267/agent-vault/docs"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer/html"
)

// DocGuide is one entry in the in-UI documentation TOC.
type DocGuide struct {
	Slug  string // empty = overview (README.md)
	Title string
	File  string
}

// DocGuides is the ordered list of human-facing guides shown in the UI.
// Keep in sync with docs/README.md (excluding superpowers/).
var DocGuides = []DocGuide{
	{Slug: "", Title: "Overview", File: "README.md"},
	{Slug: "concepts", Title: "Concepts", File: "concepts.md"},
	{Slug: "install-and-ops", Title: "Install & operations", File: "install-and-ops.md"},
	{Slug: "admin-ui", Title: "Admin UI", File: "admin-ui.md"},
	{Slug: "cli", Title: "CLI", File: "cli.md"},
	{Slug: "api", Title: "HTTP API", File: "api.md"},
	{Slug: "agents", Title: "Agents", File: "agents.md"},
	{Slug: "security-and-backup", Title: "Security & backup", File: "security-and-backup.md"},
}

var (
	mdLinkPattern   = regexp.MustCompile(`\]\((?:\./)?([a-z0-9-]+)\.md(#[^)\s]*)?\)`)
	repoLinkPattern = regexp.MustCompile(`\[([^\]]+)\]\((?:\.\./|superpowers/)[^)]+\)`)
)

var docMarkdown = goldmark.New(
	goldmark.WithExtensions(extension.GFM),
	goldmark.WithParserOptions(parser.WithAutoHeadingID()),
	goldmark.WithRendererOptions(html.WithHardWraps()),
)

type docsPageData struct {
	Title  string
	Slug   string
	Guides []DocGuide
	HTML   template.HTML
}

func guideBySlug(slug string) (DocGuide, bool) {
	for _, g := range DocGuides {
		if g.Slug == slug {
			return g, true
		}
	}
	return DocGuide{}, false
}

func rewriteDocLinks(src string) string {
	out := mdLinkPattern.ReplaceAllStringFunc(src, func(m string) string {
		sub := mdLinkPattern.FindStringSubmatch(m)
		if len(sub) < 2 {
			return m
		}
		target := sub[1]
		frag := ""
		if len(sub) > 2 {
			frag = sub[2]
		}
		if target == "README" {
			return "](/ui/docs/" + frag + ")"
		}
		if _, ok := guideBySlug(target); ok {
			return "](/ui/docs/" + target + frag + ")"
		}
		return m
	})
	// Repo-relative links (skills/, superpowers/) are not available in the UI.
	out = repoLinkPattern.ReplaceAllString(out, "$1")
	return out
}

func renderDocMarkdown(slug string) (DocGuide, template.HTML, error) {
	g, ok := guideBySlug(slug)
	if !ok {
		return DocGuide{}, "", fmt.Errorf("unknown guide")
	}
	raw, err := docs.FS.ReadFile(g.File)
	if err != nil {
		return DocGuide{}, "", err
	}
	src := rewriteDocLinks(string(raw))
	var buf bytes.Buffer
	if err := docMarkdown.Convert([]byte(src), &buf); err != nil {
		return DocGuide{}, "", err
	}
	return g, template.HTML(buf.String()), nil
}

func (s *Server) handleDocsPage(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimSpace(r.PathValue("slug"))
	slug = path.Clean("/" + slug)
	slug = strings.TrimPrefix(slug, "/")
	if slug == "." || slug == "/" {
		slug = ""
	}
	if strings.Contains(slug, "/") || strings.Contains(slug, "..") {
		http.NotFound(w, r)
		return
	}

	g, body, err := renderDocMarkdown(slug)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.renderPage(w, "docs", docsPageData{
		Title:  g.Title,
		Slug:   slug,
		Guides: DocGuides,
		HTML:   body,
	})
}
