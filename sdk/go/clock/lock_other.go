//go:build (!unix && !windows) || solaris || aix

package clock

import (
	"errors"
	"time"
)

// lockFile is unavailable here; Update still checks the state and writes it
// without a lock (rename is atomic; only concurrent updates can be lost).
func lockFile(string, time.Duration) (func(), error) {
	return nil, errors.New("file locking not supported on this platform")
}
