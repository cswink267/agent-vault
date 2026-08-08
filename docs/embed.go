package docs

import "embed"

// FS holds the human-facing markdown guides (top-level docs/*.md only).
// Design history under superpowers/ is intentionally excluded.
//
//go:embed *.md
var FS embed.FS
