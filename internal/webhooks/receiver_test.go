package webhooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// verify is docs/webhooks.md's receiver snippet, verbatim: it must accept
// what Send signs.
func verify(secret string, h http.Header, body []byte, now time.Time) bool {
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	ts, terr := strconv.ParseInt(h.Get("webhook-timestamp"), 10, 64)
	if err != nil || terr != nil || math.Abs(now.Sub(time.Unix(ts, 0)).Seconds()) > 300 {
		return false
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(h.Get("webhook-id") + "." + h.Get("webhook-timestamp") + "."))
	m.Write(body)
	want := "v1," + base64.StdEncoding.EncodeToString(m.Sum(nil))
	for _, sig := range strings.Fields(h.Get("webhook-signature")) {
		if hmac.Equal([]byte(sig), []byte(want)) {
			return true
		}
	}
	return false
}

func TestReceiverSnippet(t *testing.T) {
	cur, prev := newSecret(), newSecret()
	now := time.Now()
	body := []byte(`{"type":"license.issued"}`)
	sig, err := Signature("aud_1", now.Unix(), body, cur, prev)
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	h.Set("webhook-id", "aud_1")
	h.Set("webhook-timestamp", strconv.FormatInt(now.Unix(), 10))
	h.Set("webhook-signature", sig)
	for name, ok := range map[string]bool{
		"current secret":  verify(cur, h, body, now),
		"previous secret": verify(prev, h, body, now),
	} {
		if !ok {
			t.Errorf("%s refused", name)
		}
	}
	for name, ok := range map[string]bool{
		"another secret":   verify(newSecret(), h, body, now),
		"changed body":     verify(cur, h, []byte(`{"type":"license.revoked"}`), now),
		"replayed later":   verify(cur, h, body, now.Add(6*time.Minute)),
		"malformed secret": verify("whsec_!!", h, body, now),
	} {
		if ok {
			t.Errorf("%s accepted", name)
		}
	}
}

// The snippet in docs/webhooks.md is this file's verify, so the docs show
// tested code.
func TestReceiverSnippetInDocs(t *testing.T) {
	doc, err := os.ReadFile("../../docs/webhooks.md")
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile("receiver_test.go")
	if err != nil {
		t.Fatal(err)
	}
	extract := func(s, end string) string {
		i := strings.Index(s, "func verify(")
		if i < 0 {
			return ""
		}
		return strings.TrimSpace(s[i : i+strings.Index(s[i:], end)+len(end)])
	}
	if d, c := extract(string(doc), "\n}\n"), extract(string(src), "\n}\n"); d == "" || d != c {
		t.Errorf("docs/webhooks.md's verify differs from receiver_test.go's")
	}
}
