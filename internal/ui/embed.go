package ui

import (
	"embed"
	"html/template"
)

//go:embed templates/*
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

var pageTemplates = template.Must(template.ParseFS(templatesFS, "templates/*.html"))
