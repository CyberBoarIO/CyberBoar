package policy

import "regexp"

// namePattern and maxName are the schema's rule for metadata.name, a DNS
// label of at most maxName characters. Change them only together with the schema's
// pattern and maxLength, or IsName and the schema will disagree.
var namePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

const maxName = 63

// IsName reports whether s can be a policy's metadata.name.
func IsName(s string) bool { return len(s) <= maxName && namePattern.MatchString(s) }
