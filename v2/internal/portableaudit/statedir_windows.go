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

// writePrivate на Windows создаёт файл через приватный корень (тот же путь, что и чтение privatefile.Read):
// файл получает DACL корня, без наследования прав родителя (CI windows-2022: collect не принимал ключ, записанный
// обычным os.OpenFile).
func writePrivate(dir, name string, b []byte) error {
	root, e := winstate.OpenRoot(dir)
	if e != nil {
		return e
	}
	defer root.Close()
	return root.CreateNew(name, b)
}

// replacePrivate на Windows — атомарная замена в приватном корне под его блокировкой.
func replacePrivate(dir, name string, b []byte) error {
	root, e := winstate.OpenRoot(dir)
	if e != nil {
		return e
	}
	defer root.Close()
	unlock, e := root.Lock()
	if e != nil {
		return e
	}
	defer unlock()
	return root.AtomicReplace(name, b)
}
