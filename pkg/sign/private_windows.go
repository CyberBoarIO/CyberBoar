package sign

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// writePrivate applies a protected DACL at creation, before writing key bytes.
// POSIX mode 0600 does not restrict an inherited Windows ACL.
func writePrivate(path string, data []byte) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sddl := "D:P(A;;FA;;;SY)"
	if !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		sddl += "(A;;FA;;;" + user.User.Sid.String() + ")"
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return &os.PathError{Op: "create", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(h), path)
	// Verify that the filesystem honored the descriptor before any secret bytes are written
	// Filesystems without ACL support must fail closed
	err = checkPrivateACL(h, user.User.Sid)
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
	}
	return err
}

func checkPrivateACL(h windows.Handle, user *windows.SID) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 || dacl == nil || dacl.AceCount == 0 || dacl.AceCount > 2 {
		return errors.New("private signing key requires a protected owner/SYSTEM ACL")
	}
	seenUser, seenSystem := false, false
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 {
			return errors.New("private signing key has an unexpected ACL entry")
		}
		// #nosec G103 -- the Windows ACCESS_ALLOWED_ACE SID starts at SidStart
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.Equals(user) {
			seenUser = true
		} else if !sid.IsWellKnown(windows.WinLocalSystemSid) {
			return errors.New("private signing key is accessible to another account")
		}
		if sid.IsWellKnown(windows.WinLocalSystemSid) {
			seenSystem = true
		}
	}
	if !seenUser || !seenSystem {
		return errors.New("private signing key ACL must grant its owner and SYSTEM access")
	}
	return nil
}
