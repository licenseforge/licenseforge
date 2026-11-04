//go:build !webui

package web

import "embed"

// The real bundle needs Node to build; without the webui tag, serve a page
// that says how to get it.
//
//go:embed placeholder
var files embed.FS

const root = "placeholder"
