//go:build webui

package web

import "embed"

//go:embed all:dist
var files embed.FS

const root = "dist"

// Embedded reports whether the real dashboard bundle is in the binary.
const Embedded = true
