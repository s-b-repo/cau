//go:build !linux && !windows && !darwin

package inventory

import "context"

func platformCollections(context.Context) []Collection {
	return []Collection{{Provider: "system-packages", Scope: "system", Status: Unsupported, Reason: "no software inventory provider for this operating system"}}
}
