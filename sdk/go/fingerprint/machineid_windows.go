package fingerprint

import (
	"errors"
	"syscall"
	"unsafe"
)

const keyWOW6464Key = 0x0100 // read the 64-bit registry view from 32-bit processes too

func osMachineID() (string, error) {
	path, _ := syscall.UTF16PtrFromString(`SOFTWARE\Microsoft\Cryptography`)
	name, _ := syscall.UTF16PtrFromString("MachineGuid")
	var h syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, path, 0, syscall.KEY_READ|keyWOW6464Key, &h); err != nil {
		return "", err
	}
	defer syscall.RegCloseKey(h)
	var typ uint32
	var buf [128]uint16
	n := uint32(len(buf) * 2)
	if err := syscall.RegQueryValueEx(h, name, nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &n); err != nil {
		return "", err
	}
	if typ != syscall.REG_SZ {
		return "", errors.New("MachineGuid is not a string")
	}
	id := syscall.UTF16ToString(buf[:n/2])
	if id == "" {
		return "", errors.New("empty MachineGuid")
	}
	return id, nil
}
