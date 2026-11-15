// Package warehouse — склад и жизненный цикл оборудования (волна 2, C41–C45; проект decisions/C41-w2-scope-and-model.md):
// места, каталог, серийные экземпляры, количественные остатки, резервы и журнал движений. Пишет только в схему
// warehouse; активы, ответственность и инвентаризацию только читает.
package warehouse

import (
	"embed"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/migrate"
)

//go:embed schema/*.sql
var files embed.FS

func Migrations() ([]migrate.Migration, error) { return migrate.FromFS("warehouse", files) }
