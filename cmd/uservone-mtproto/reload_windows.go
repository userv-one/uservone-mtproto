//go:build windows

package main

import "os"

func reloadSignalChannel() <-chan os.Signal {
	return nil
}
