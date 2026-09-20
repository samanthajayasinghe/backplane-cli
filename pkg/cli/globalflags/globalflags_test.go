package globalflags

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestAddGlobalFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	opts := &GlobalOptions{}
	AddGlobalFlags(cmd, opts)

	tests := []struct {
		name     string
		flagName string
	}{
		{"url flag", "url"},
		{"proxy flag", "proxy"},
		{"no-proxy flag", "no-proxy"},
		{"manager flag", "manager"},
		{"service flag", "service"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := cmd.PersistentFlags().Lookup(tt.flagName)
			if flag == nil {
				t.Errorf("expected flag %q to be registered", tt.flagName)
			}
		})
	}
}

func TestNoProxyFlagDefaults(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	opts := &GlobalOptions{}
	AddGlobalFlags(cmd, opts)

	if opts.NoProxy {
		t.Error("expected NoProxy to default to false")
	}
}

func TestNoProxyFlagCanBeSet(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	opts := &GlobalOptions{}
	AddGlobalFlags(cmd, opts)

	err := cmd.PersistentFlags().Set("no-proxy", "true")
	if err != nil {
		t.Fatalf("failed to set no-proxy flag: %v", err)
	}

	if !opts.NoProxy {
		t.Error("expected NoProxy to be true after setting flag")
	}
}
