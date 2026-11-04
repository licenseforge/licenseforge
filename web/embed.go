// Package web serves the admin dashboard (ADR-0020), a single-page app built
// from this directory into dist/ and embedded in the binary.
//
// The bundle is embedded only with the webui build tag (`make web build
// TAGS=webui`), so go build, go test and CI work without Node; without the
// tag a placeholder page is served instead.
package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
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

// Mount serves the dashboard on mux as the catch-all "/". It is method-less
// so that method-less subtrees like the API's "/api/v1/" can coexist (a
// "GET /" would conflict with them and make ServeMux panic). The mux's own
// 405 is kept: a request that reaches "/" while mux routes its path for
// other methods (GET /auth/logout, POST /healthz) gets 405 with Allow (as
// problem JSON under /api/, ADR-0032). Other methods on dashboard paths get
// 405 too; everything else gets the app or the handler's 404.
func Mount(mux *http.ServeMux) {
	spa := Handler()
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := path.Clean("/" + r.URL.Path)
		var allow []string // methods with their own route for this path
		for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			probe := *r // mux.Handler reads only Method, Host and URL
			probe.Method = m
			if _, pattern := mux.Handler(&probe); pattern != "" && pattern != "/" {
				allow = append(allow, m)
				if m == http.MethodGet {
					allow = append(allow, http.MethodHead)
				}
			}
		}
		if len(allow) == 0 {
			// The app (GET, HEAD; 405 otherwise) or the handler's 404s.
			spa.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Allow", strings.Join(allow, ", "))
		if under(p, "/api") {
			problem(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}))
}

// serverPath reports whether p belongs to the server, never the app.
func serverPath(p string) bool {
	return under(p, "/api") || under(p, "/auth") || p == "/healthz" || p == "/readyz"
}

// Handler serves the dashboard: files from the bundle, and index.html for
// any other path so the app's router handles it. It never answers for the
// server's own paths (/api/, /auth/, /healthz, /readyz) if they reach it
// unmatched: those get a 404, as problem JSON under /api/.
func Handler() http.Handler {
	sub, err := fs.Sub(files, root)
	if err != nil {
		panic(err)
	}
	return newHandler(sub)
}

type file struct {
	data []byte
	etag string // validator, so no-cache files can answer 304
}

// newHandler loads the whole bundle (it is embedded, so already in memory)
// and hashes each file once.
func newHandler(fsys fs.FS) http.Handler {
	files := map[string]file{}
	err := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(fsys, name)
		sum := sha256.Sum256(b)
		files[name] = file{b, `"` + base64.RawURLEncoding.EncodeToString(sum[:16]) + `"`}
		return err
	})
	if err != nil {
		panic(err)
	}
	if _, ok := files["index.html"]; !ok {
		panic("web: bundle without index.html")
	}
	return &handler{files: files}
}

type handler struct{ files map[string]file }

// problem writes an RFC 9457 error, like the API's own (ADR-0032).
func problem(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"type":"about:blank","title":%q,"status":%d,"code":%q}`+"\n", http.StatusText(status), status, code)
}

// under reports whether p is prefix or below it.
func under(p, prefix string) bool { return p == prefix || strings.HasPrefix(p, prefix+"/") }

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hd := w.Header()
	hd.Set("Content-Security-Policy", csp)
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Referrer-Policy", "same-origin")
	p := path.Clean("/" + r.URL.Path)
	if under(p, "/api") {
		problem(w, http.StatusNotFound, "not_found")
		return
	}
	if serverPath(p) {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		hd.Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(p, "/")
	f, ok := h.files[name]
	switch {
	case ok && strings.HasPrefix(name, "assets/"): // content-hashed names (Vite)
		hd.Set("Cache-Control", "public, max-age=31536000, immutable")
	case ok:
		hd.Set("Cache-Control", "no-cache")
	case under(p, "/assets"): // a stale index.html's asset: don't answer with HTML
		http.NotFound(w, r)
		return
	default:
		name, f = "index.html", h.files["index.html"]
		hd.Set("Cache-Control", "no-cache")
	}
	hd.Set("ETag", f.etag)
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(f.data))
}
