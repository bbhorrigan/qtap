//go:build !linux

package cmd

import (
	"github.com/spf13/cobra"
)

var tapCmd = &cobra.Command{
	Use:   "tap",
	Short: "Tap into traffic streams and analyze without a proxy",
	Long: `Tap into traffic streams and analyze without a proxy.
Example usage:
  qpoint tap --tls-probes="openssl" --http-buffer-size="1mb"`,
	Run: func(cmd *cobra.Command, args []string) {
		logger := initLogger()
		defer syncLogger(logger)

		logger.Fatal("'tap' leverages eBPF probes which can only run on Linux.")
	},
}
