package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/userv-one/uservone-mtproto/core"
)

const version = "uservone-mtproto"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(version, flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "config.json", "path to JSON configuration")
	checkConfig := flags.Bool("check-config", false, "validate configuration and exit")
	linksHost := flags.String("links-host", "", "print Telegram links for this public host and exit")
	showVersion := flags.Bool("version", false, "print version and exit")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}

	cfg, err := core.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "configuration error: %v\n", err)
		return 1
	}
	proxy, err := core.New(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "initialization error: %v\n", err)
		return 1
	}
	if *checkConfig {
		fmt.Fprintln(stdout, "configuration OK")
	}
	if *linksHost != "" {
		links, err := proxy.Links(*linksHost)
		if err != nil {
			fmt.Fprintf(stderr, "link generation error: %v\n", err)
			return 1
		}
		for _, link := range links {
			fmt.Fprintf(stdout, "%s [%s] %s\n", link.User, link.Transport, link.URL)
		}
	}
	if *checkConfig || *linksHost != "" {
		return 0
	}

	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		fmt.Fprintf(stderr, "listen error: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger := log.New(stderr, version+": ", log.LstdFlags)
	logger.Printf("listening on %s (dd=%t, fake-TLS=%t, mask=%t)", cfg.Listen, cfg.EnableSecure, cfg.EnableTLS, cfg.Mask)
	if err := proxy.Serve(ctx, listener); err != nil {
		logger.Printf("server error: %v", err)
		return 1
	}
	logger.Print("stopped")
	return 0
}
