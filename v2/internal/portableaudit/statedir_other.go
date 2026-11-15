//go:build !windows

package portableaudit

import "os"

// privateDir — каталог личности только для владельца (0700).
func privateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}
