//go:build !windows

package hostrealm

func registryDefaultRealm() string {
	return ""
}
