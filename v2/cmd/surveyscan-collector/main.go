package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/QgMixtate/surveyscan/v2/internal/collector"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/buildinfo"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func run(args []string) error {
	if len(args) == 1 && (args[0] == "version" || args[0] == "--version") {
		return buildinfo.Print(os.Stdout, "collector")
	}
	if len(args) > 0 && args[0] == "register" {
		return register(args[1:])
	}
	if handled, e := runServiceCommand(args); handled {
		return e
	}
	if len(args) == 0 || (args[0] != "run" && args[0] != "renew") {
		return fmt.Errorf("supported commands: register (установка по коду), run/renew --config PRIVATE_FILE, version; Windows: service, start-service")
	}
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "", "")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *path == "" {
		return fmt.Errorf("private collector configuration required")
	}
	relay, e := collector.Load(*path)
	if e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if args[0] == "renew" {
		task, stop := context.WithTimeout(ctx, 30*time.Second)
		defer stop()
		if e = relay.RenewOnce(task); e != nil {
			return e
		}
		fmt.Println("collector_certificate_renewed")
		return nil
	}
	wireTargets(relay)
	fmt.Println("collector HTTPS relay started; pending data retained until verified center result")
	return relay.Run(ctx)
}

// register — установка по коду из Web (C52.01). Код можно передать переменной SURVEYSCAN_REGISTRATION_CODE.
func register(args []string) error {
	flags := flag.NewFlagSet("register", flag.ContinueOnError)
	center := flags.String("center", "", "https://адрес центра")
	code := flags.String("code", "", "код регистрации из Web")
	fingerprint := flags.String("fingerprint", "", "отпечаток центра из Web")
	dir := flags.String("dir", "", "каталог конфигурации и ключей")
	state := flags.String("state", "", "каталог состояния")
	listen := flags.String("listen", "0.0.0.0:8443", "адрес приёма агентов")
	ifUnregistered := flags.Bool("if-unregistered", false, "уже зарегистрирован — не ошибка (установщик MSI)")
	if e := flags.Parse(args); e != nil {
		return e
	}
	if *ifUnregistered && *dir != "" {
		if _, e := os.Stat(filepath.Join(*dir, "collector.json")); e == nil {
			fmt.Println("already_registered")
			return nil
		}
	}
	if *code == "" {
		*code = os.Getenv("SURVEYSCAN_REGISTRATION_CODE")
	}
	if flags.NArg() != 0 || *center == "" || *code == "" || *fingerprint == "" || *dir == "" || *state == "" {
		return fmt.Errorf("register --center URL --code КОД --fingerprint ОТПЕЧАТОК --dir КАТАЛОГ --state КАТАЛОГ [--listen 0.0.0.0:8443]")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	source, e := collector.Register(ctx, collector.RegisterOptions{CenterURL: *center, Code: *code, Fingerprint: *fingerprint, Dir: *dir, StateDir: *state, Listen: *listen})
	if e != nil {
		return e
	}
	fmt.Println("collector_registered " + source)
	return nil
}

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
