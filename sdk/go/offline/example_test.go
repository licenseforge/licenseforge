package offline_test

import (
	"bytes"
	"errors"
	"io/fs"
	"log"
	"os"
	"time"

	"licenseforge.io/licenseforge/sdk/go/clock"
	"licenseforge.io/licenseforge/sdk/go/offline"
)

// A license file delivered by a secret manager (docs/secret-managers.md),
// mounted as a directory: installed at start and again whenever it changes.
// Run it in its own goroutine.
func ExampleClient_Install_mounted() {
	var c *offline.Client // from offline.New
	const path = "/etc/acme/license/license.lic"
	var last []byte
	for ; ; time.Sleep(time.Minute) {
		b, err := os.ReadFile(path)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) { // not synced yet: quietly wait
				log.Printf("license file: %v", err)
			}
			continue
		}
		if bytes.Equal(b, last) {
			continue
		}
		_, _, err = c.Install(string(b))
		if errors.Is(err, clock.ErrLocked) {
			continue // another process is changing the state: retry
		}
		if err != nil {
			log.Printf("license file %s: %v", path, err) // once per file; the installed one, if any, stays
		}
		last = b
	}
}
