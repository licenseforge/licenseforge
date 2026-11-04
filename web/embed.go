// Package web serves the admin dashboard (ADR-0020), a single-page app built
// from this directory into dist/ and embedded in the binary.
//
// The bundle is embedded only with the webui build tag (`make web build
// TAGS=webui`), so go build, go test and CI work without Node; without the
// tag a placeholder page is served instead.
package web

import (
	"bytes"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

// csp allows only the app's own files: no inline scripts or styles, no
// framing, no <base> or off-site form targets.
const csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
	"object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// Handler serves the dashboard at /: files from the bundle, and index.html
// for any other path so the app's router handles it. It never answers for
// the server's own paths (/api/, /auth/, /healthz, /readyz) if they reach it
// unmatched: those get a 404, as JSON under /api/.
func Handler() http.Handler {
	sub, err := fs.Sub(files, root)
	if err != nil {
		panic(err)
	}
	return newHandler(sub)
}

func newHandler(files fs.FS) http.Handler {
	index, err := fs.ReadFile(files, "index.html")
	if err != nil {
		panic("web: bundle without index.html: " + err.Error())
	}
	return &handler{files: files, index: index}
}

type handler struct {
	files fs.FS
	index []byte
}

// under reports whether p is prefix or below it.
func under(p, prefix string) bool { return p == prefix || strings.HasPrefix(p, prefix+"/") }

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hd := w.Header()
	hd.Set("Content-Security-Policy", csp)
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Referrer-Policy", "same-origin")
	p := path.Clean("/" + r.URL.Path)
	if under(p, "/api") { // RFC 9457, like the API's own errors (ADR-0032)
		hd.Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"type":"about:blank","title":"Not Found","status":404,"code":"not_found"}` + "\n"))
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		hd.Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if under(p, "/auth") || p == "/healthz" || p == "/readyz" {
		http.NotFound(w, r)
		return
	}
	name := strings.TrimPrefix(p, "/")
	if b, err := fs.ReadFile(h.files, name); err == nil {
		if strings.HasPrefix(name, "assets/") { // content-hashed names (Vite)
			hd.Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			hd.Set("Cache-Control", "no-cache")
		}
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(b))
		return
	}
	if under(p, "/assets") { // a stale index.html's asset: don't answer with HTML
		http.NotFound(w, r)
		return
	}
	hd.Set("Cache-Control", "no-cache")
	http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(h.index))
}
