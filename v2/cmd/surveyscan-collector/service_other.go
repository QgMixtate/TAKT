//go:build !windows

package main

// runServiceCommand — службы Windows нет: на Linux collector запускает systemd (пакеты deb/rpm, C52.04).
func runServiceCommand([]string) (bool, error) { return false, nil }
