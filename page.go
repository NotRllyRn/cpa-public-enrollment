package main

import (
	_ "embed"
	"html"
	"strings"
)

//go:embed web/index.html
var page string

// The only substitution is in an HTML text node, never markup or script.
func enrollmentPage(operatorName string) string {
	name := strings.TrimSpace(operatorName)
	if name == "" {
		name = "Not specified"
	}
	return strings.Replace(page, "{{OPERATOR_NAME}}", html.EscapeString(name), 1)
}

//go:embed web/app.js
var script string

//go:embed web/enroll.css
var stylesheet string
