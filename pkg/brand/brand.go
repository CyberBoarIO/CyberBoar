// Package brand defines shared product and policy identifiers.
package brand

const (
	// Name of the CLI binary.
	Name = "cyberboar"

	// DisplayName is the product name in prose and page titles.
	DisplayName = "CyberBoar"

	// APIGroup is the group part of the policy apiVersion.
	APIGroup = "cyberboar.dev"

	// APIVersion is the supported policy apiVersion.
	APIVersion = APIGroup + "/v1"

	// EnvPrefix is the prefix for CyberBoar-specific environment variables.
	EnvPrefix = "CYBERBOAR_"
)
