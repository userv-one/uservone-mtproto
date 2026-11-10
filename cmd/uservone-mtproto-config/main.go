package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/userv-one/uservone-mtproto/compat"
	"github.com/userv-one/uservone-mtproto/core"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, _ io.Writer, stderr io.Writer) int {
	defaults := core.DefaultConfig()
	flags := flag.NewFlagSet("uservone-mtproto-config", flag.ContinueOnError)
	flags.SetOutput(stderr)
	inputPath := flags.String("input", "", "path to the entitled-record JSON array")
	outputPath := flags.String("output", "", "path for the generated proxy JSON config")
	listen := flags.String("listen", defaults.Listen, "proxy listen address")
	tlsDomain := flags.String("tls-domain", defaults.TLSDomain, "fake-TLS domain")
	maskHost := flags.String("mask-host", "", "HTTPS mask host (defaults to the TLS domain)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *inputPath == "" || *outputPath == "" {
		fmt.Fprintln(stderr, "-input and -output are required")
		return 2
	}
	if *maskHost == "" {
		*maskHost = *tlsDomain
	}

	input, err := os.ReadFile(*inputPath)
	if err != nil {
		fmt.Fprintf(stderr, "read input: %v\n", err)
		return 1
	}
	cfg, err := compat.GenerateJSON(input, compat.Options{
		Listen: *listen, TLSDomain: *tlsDomain, MaskHost: *maskHost,
	})
	if err != nil {
		fmt.Fprintf(stderr, "generate config: %v\n", err)
		return 1
	}
	output, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "encode config: %v\n", err)
		return 1
	}
	output = append(output, '\n')
	if err := writeFileAtomic(*outputPath, output); err != nil {
		fmt.Fprintf(stderr, "write config: %v\n", err)
		return 1
	}
	return 0
}

func writeFileAtomic(path string, contents []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}()
	if err := temp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temp.Write(contents); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}
