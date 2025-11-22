package main

import (
	"flag"
	"io"
	"testing"
)

func TestDBCommandConfigFlag(t *testing.T) {
	t.Run("default config path", func(t *testing.T) {
		fs, configPath := newDBFlagSet(flag.ContinueOnError)
		fs.SetOutput(io.Discard)

		if err := fs.Parse(nil); err != nil {
			t.Fatalf("failed to parse flags: %v", err)
		}

		if got := *configPath; got != defaultConfigPath {
			t.Fatalf("expected default config path %q, got %q", defaultConfigPath, got)
		}
	})

	t.Run("custom config path", func(t *testing.T) {
		fs, configPath := newDBFlagSet(flag.ContinueOnError)
		fs.SetOutput(io.Discard)

		customPath := "/tmp/custom-config.yaml"
		if err := fs.Parse([]string{"--config", customPath}); err != nil {
			t.Fatalf("failed to parse flags: %v", err)
		}

		if got := *configPath; got != customPath {
			t.Fatalf("expected config path %q, got %q", customPath, got)
		}
	})
}
