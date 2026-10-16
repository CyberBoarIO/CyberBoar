package enroll

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// currentUser returns the SID the process runs as.
func currentUser() (*windows.SID, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return tu.User.Sid.Copy()
}

// trusted reports whether sid may own or access an endpoint's state. Only
// the current user, SYSTEM, the Administrators group (who can take ownership
// of anything anyway) and OWNER RIGHTS may.
func trusted(sid, user *windows.SID) bool {
	return sid.Equals(user) || sid.IsWellKnown(windows.WinLocalSystemSid) ||
		sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.IsWellKnown(windows.WinCreatorOwnerRightsSid)
}

// securePath gives path a protected DACL that grants full control to SYSTEM
// and the current user only, inherited by what a directory will hold, and
// refuses a path an untrusted account owns. Under C:\ProgramData a new
// directory would otherwise inherit read access for every user.
func securePath(path string, fi os.FileInfo) error {
	user, err := currentUser()
	if err != nil {
		return err
	}
	if err := checkOwner(path, user); err != nil {
		return err
	}
	if fi == nil {
		if fi, err = os.Lstat(path); err != nil {
			return err
		}
	}
	inherit := ""
	if fi.IsDir() {
		inherit = "OICI"
	}
	sddl := "D:P(A;" + inherit + ";FA;;;SY)"
	if !user.IsWellKnown(windows.WinLocalSystemSid) {
		sddl += "(A;" + inherit + ";FA;;;" + user.String() + ")"
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// checkOwner refuses a path owned by an account that is neither user, SYSTEM,
// Administrators nor OWNER RIGHTS (see trusted).
func checkOwner(path string, user *windows.SID) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%s: reading its owner: %v", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("%s: reading its owner: %v", path, err)
	}
	if owner == nil || !trusted(owner, user) {
		return fmt.Errorf("%s is owned by %v, not by this user, SYSTEM or Administrators", path, owner)
	}
	return nil
}

// checkPrivate refuses a file or directory owned by an untrusted account, or
// whose DACL lets any other account in. Inherited entries count, because
// the DACL read here is the effective one.
func checkPrivate(path string, _ os.FileInfo) error {
	user, err := currentUser()
	if err != nil {
		return err
	}
	if err := checkOwner(path, user); err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%s: reading its access control list: %v", path, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		// A missing DACL grants everyone full access.
		return fmt.Errorf("%s has no access control list: everyone may access it", path)
	}
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("%s: reading its access control list: %v", path, err)
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue // applies to what a directory holds, not to it
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			// #nosec G103 -- an ACE's SID starts at SidStart, as in Microsoft's documentation.
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !trusted(sid, user) {
				return fmt.Errorf("%s is accessible to %s; only SYSTEM, Administrators and its owner may have access", path, sid)
			}
		default:
			return fmt.Errorf("%s has an access control entry of a kind (%d) this check doesn't read", path, ace.Header.AceType)
		}
	}
	return nil
}
