//go:build !unix && !windows

package clock

import (
	"errors"
	"time"
)

// lockFile is unavailable here; Update still reads and checks the state but
// does not write it.
func lockFile(string, time.Duration) (func(), error) {
	return nil, errors.New("file locking not supported on this platform")
}
