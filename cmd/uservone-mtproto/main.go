package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/userv-one/uservone-mtproto/core"
)

const appName = "uservone-mtproto"

var version = "v0.3.0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(appName, flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "config.json", "path to JSON configuration")
	checkConfig := flags.Bool("check-config", false, "validate configuration and exit")
	linksHost := flags.String("links-host", "", "print Telegram links for this public host and exit")
	format := flags.String("format", "text", "links output format: text or json")
	showVersion := flags.Bool("version", false, "print version and exit")
	showVersionJSON := flags.Bool("version-json", false, "print version information as JSON and exit")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "%s %s\n", appName, version)
		return 0
	}
	if *showVersionJSON {
		return writeJSON(stdout, map[string]string{
			"name": appName, "version": version, "go_version": runtime.Version(),
		}, stderr)
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintln(stderr, "format must be text or json")
		return 2
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
		if *format == "json" {
			if code := writeJSON(stdout, links, stderr); code != 0 {
				return code
			}
		} else {
			for _, link := range links {
				fmt.Fprintf(stdout, "%s [%s] %s\n", link.User, link.Transport, link.URL)
			}
		}
	}
	if *checkConfig || *linksHost != "" {
		return 0
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger := log.New(stderr, appName+": ", log.LstdFlags)
	if cfg.EnableTLS && cfg.Mask && cfg.MatchMaskHost && cfg.FakeCertLen == 0 {
		if err := proxy.RefreshMaskProfile(ctx); err != nil {
			logger.Printf("mask host probe failed: %v", err)
			return 1
		}
	}
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		fmt.Fprintf(stderr, "listen error: %v\n", err)
		return 1
	}
	if err := startMetrics(ctx, cfg.MetricsListen, proxy, logger); err != nil {
		_ = listener.Close()
		logger.Printf("metrics listener error: %v", err)
		return 1
	}
	watchReload(ctx, *configPath, proxy, logger)
	logger.Printf("listening on %s (dd=%t, fake-TLS=%t, mask=%t)", cfg.Listen, cfg.EnableSecure, cfg.EnableTLS, cfg.Mask)
	if err := proxy.Serve(ctx, listener); err != nil {
		logger.Printf("server error: %v", err)
		return 1
	}
	logger.Print("stopped")
	return 0
}

func writeJSON(stdout io.Writer, value any, stderr io.Writer) int {
	if err := json.NewEncoder(stdout).Encode(value); err != nil {
		fmt.Fprintf(stderr, "JSON output error: %v\n", err)
		return 1
	}
	return 0
}

func startMetrics(ctx context.Context, listen string, proxy *core.Proxy, logger *log.Logger) error {
	if listen == "" {
		return nil
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", proxy.Metrics().PrometheusHandler())
	mux.Handle("/health", proxy.Metrics().HealthHandler())
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			logger.Printf("metrics server error: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	return nil
}

func watchReload(ctx context.Context, configPath string, proxy *core.Proxy, logger *log.Logger) {
	reload := reloadSignalChannel()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-reload:
				cfg, err := core.LoadConfig(configPath)
				if err == nil {
					err = proxy.ReloadUsers(cfg.Users, time.Duration(cfg.RotationGraceSeconds)*time.Second)
				}
				if err != nil {
					logger.Printf("secret reload failed: %v", err)
					continue
				}
				logger.Print("secrets reloaded")
			}
		}
	}()
}
