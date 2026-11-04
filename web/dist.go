//go:build webui

package web

import "embed"

//go:embed all:dist
var files embed.FS

const root = "dist"
