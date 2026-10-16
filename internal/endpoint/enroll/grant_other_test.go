//go:build !windows

package enroll

func grantUsers(string) error { panic("Windows only") }
