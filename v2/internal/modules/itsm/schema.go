// Package itsm — обращения (волна 3, C46–C50; проект decisions/C46-w3-itsm-scope-and-model.md): инциденты, заявки,
// изменения и проблемы, их журнал, связи и согласования. Пишет только в схему itsm; активы, сервисы,
// ответственность и склад только читает и ссылается на них по ID — своего каталога активов нет.
package itsm

import (
	"embed"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/migrate"
)

//go:embed schema/*.sql
var files embed.FS

func Migrations() ([]migrate.Migration, error) { return migrate.FromFS("itsm", files) }
