package offline_test

import (
	"bytes"
	"log"
	"os"
	"time"

	"licenseforge.io/licenseforge/sdk/go/offline"
)

// A license file delivered by a secret manager (docs/secret-managers.md),
// mounted as a directory: installed at start and again whenever it changes.
func ExampleClient_Install_mounted() {
	var c *offline.Client // from offline.New
	const path = "/etc/acme/license/license.lic"
	var last []byte
	for ; ; time.Sleep(time.Minute) {
		b, err := os.ReadFile(path)
		if err != nil || bytes.Equal(b, last) {
			continue // missing (not synced yet) or unchanged
		}
		if _, _, err := c.Install(string(b)); err != nil {
			log.Printf("license file %s: %v", path, err) // the installed file, if any, stays
			continue
		}
		last = b
	}
}
