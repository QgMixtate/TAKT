//go:build !windows

package portableaudit

import (
	"os"
	"path/filepath"
)

// privateDir — каталог личности только для владельца (0700).
func privateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}

// writePrivate создаёт новый файл 0600 (существующий не перезаписывается).
func writePrivate(dir, name string, b []byte) error {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// replacePrivate атомарно заменяет файл (временный 0600 + rename в том же каталоге).
func replacePrivate(dir, name string, b []byte) error {
	tmp := filepath.Join(dir, name+".tmp")
	_ = os.Remove(tmp)
	if err := writePrivate(dir, name+".tmp", b); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, name))
}
