package clock

import (
	"os"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = kernel32.NewProc("LockFileEx")
	procUnlockFileEx = kernel32.NewProc("UnlockFileEx")
)

const (
	lockfileFailImmediately = 0x1
	lockfileExclusiveLock   = 0x2
	errorLockViolation      = syscall.Errno(33) // ERROR_LOCK_VIOLATION: held by another process
)

// lockFile takes an exclusive LockFileEx lock on path, waiting up to wait.
// Windows releases it when the process exits, so there are no stale locks.
func lockFile(path string, wait time.Duration) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	h := f.Fd()
	deadline := time.Now().Add(wait)
	for {
		var ol syscall.Overlapped
		r, _, callErr := procLockFileEx.Call(h, lockfileExclusiveLock|lockfileFailImmediately, 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
		if r != 0 {
			return func() {
				var ol syscall.Overlapped
				_, _, _ = procUnlockFileEx.Call(h, 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
				_ = f.Close()
			}, nil
		}
		if callErr != errorLockViolation {
			_ = f.Close()
			return nil, callErr
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, errLockBusy
		}
		time.Sleep(10 * time.Millisecond)
	}
}
