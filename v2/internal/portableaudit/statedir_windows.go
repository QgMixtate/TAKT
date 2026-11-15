//go:build windows

package portableaudit

import (
	"os"
	"path/filepath"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/winstate"
)

// privateDir на Windows создаёт каталог личности как приватный корень (защищённый DACL), как у агента: иначе
// ключ подписи унаследовал бы права родителя, а чтение личных файлов его отвергло бы. Существующий каталог
// проверяется, а не «исправляется».
func privateDir(dir string) error {
	if _, e := os.Lstat(dir); e == nil {
		root, e := winstate.OpenRoot(dir)
		if e != nil {
			return e
		}
		return root.Close()
	} else if !os.IsNotExist(e) {
		return e
	}
	if e := os.MkdirAll(filepath.Dir(dir), 0o700); e != nil {
		return e
	}
	root, e := winstate.CreateRoot(dir)
	if e != nil {
		return e
	}
	return root.Close()
}
