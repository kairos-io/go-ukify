package main

import (
	"encoding/json"
	"fmt"
	"github.com/itxaka/go-ukify/pkg/constants"
	"github.com/itxaka/go-ukify/pkg/measure"
	"github.com/itxaka/go-ukify/pkg/pesign"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log/slog"
	"os"
)

type section struct {
	// Section name.
	Name constants.Section
	// Path to the contents of the section.
	Path string
	// Should the section be measured to the TPM?
	Measure bool
	// Should the section be appended, or is it already in the PE file.
	Append bool
	// Size & VMA of the section.
	Size uint64
	VMA  uint64
}

func main() {
	c := cobra.Command{
		Use: "measure FILE",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if viper.GetString("pcr-key") == "" {
				return fmt.Errorf("pcr-key is required")
			}
			if len(args) == 0 {
				return fmt.Errorf("file is required")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			switch viper.GetString("log-level") {
			case "debug":
				slog.SetLogLoggerLevel(slog.LevelDebug)
			case "info":
				slog.SetLogLoggerLevel(slog.LevelInfo)
			case "warn":
				slog.SetLogLoggerLevel(slog.LevelWarn)
			case "error":
				slog.SetLogLoggerLevel(slog.LevelError)
			default:
				slog.SetLogLoggerLevel(slog.LevelInfo)
			}
			output := viper.GetString("output")
			key := viper.GetString("pcr-key")
			slog.Info("Starting to measure", "file", args[0], "output", output, "pcr-key", key)
			signer, err := pesign.NewPCRSigner(key)
			if err != nil {
				return err
			}

			measurements, err := measure.GenerateSignedPCRForBytes(args[0], signer, 13)
			if err != nil {
				slog.Info("Failed to generate signed PCR")
				return err
			}
			slog.Debug("Generated signed PCR", "measurements", measurements)

			jsonData, err := json.Marshal(measurements)
			if err != nil {
				return err
			}
			err = os.WriteFile(output, jsonData, os.ModePerm)
			if err != nil {
				return err
			}
			slog.Info("Finished measuring", "file", args[0], "output", output, "pcr-key", key)
			return nil
		},
	}

	c.Flags().StringP("pcr-key", "p", "", "PCR key.")
	c.Flags().StringP("output", "o", "measurements.json", "Output file for measurements in json format.")
	c.Flags().String("log-level", "info", "Log level.")
	// Set flag as required
	err := c.MarkFlagRequired("pcr-key")

	err = viper.BindPFlags(c.Flags())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if err := c.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
