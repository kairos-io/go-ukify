package cmd

import (
	"github.com/spf13/cobra"
	"os"
)

func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use: "ukify",
	}

	cmd.CompletionOptions = cobra.CompletionOptions{
		DisableDefaultCmd: true,
	}
	return cmd
}

var rootCmd = NewRootCmd()

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
