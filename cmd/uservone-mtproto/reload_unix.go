//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

func reloadSignalChannel() <-chan os.Signal {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP)
	return signals
}
