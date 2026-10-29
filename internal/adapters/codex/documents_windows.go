package codex

import "golang.org/x/sys/windows"

// documentsDir returns the user's Documents folder, which holds PowerShell's
// profiles and modules. It can be redirected, as OneDrive does, so Windows is
// asked for it. It returns "" if Windows doesn't know it.
func documentsDir() string {
	dir, err := windows.KnownFolderPath(windows.FOLDERID_Documents, 0)
	if err != nil {
		return ""
	}
	return dir
}
