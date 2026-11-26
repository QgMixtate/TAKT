//go:build windows

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/QgMixtate/surveyscan/v2/internal/collector"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/winservice"
)

// Имя службы collector в SCM; его создаёт MSI (C52.04), агент — SurveyscanAgent.
const defaultServiceName = "SurveyscanCollector"

// runServiceCommand — служба Windows (C52.04): `service` — вход SCM, `start-service` — запуск только
// у зарегистрированного collector (есть конфигурация), иначе — подсказка без ошибки (MSI без кода).
func runServiceCommand(args []string) (bool, error) {
	if len(args) == 0 || (args[0] != "service" && args[0] != "start-service") {
		return false, nil
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	name := flags.String("name", defaultServiceName, "service name")
	path := flags.String("config", "", "collector.json (absolute path)")
	if e := flags.Parse(args[1:]); e != nil {
		return true, e
	}
	if flags.NArg() != 0 || *path == "" {
		return true, fmt.Errorf("%s --config ПУТЬ [--name ИМЯ]", args[0])
	}
	if args[0] == "start-service" {
		if _, e := os.Stat(*path); e != nil {
			fmt.Println("not_registered: служба запустится после surveyscan-collector register")
			return true, nil
		}
		if e := winservice.Start(*name); e != nil {
			return true, e
		}
		fmt.Println("service_started")
		return true, nil
	}
	relay, e := collector.Load(*path)
	if e != nil {
		return true, e
	}
	wireTargets(relay)
	return true, winservice.Run(*name, func(ctx context.Context) error {
		if err := relay.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		return nil
	})
}
