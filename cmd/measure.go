package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/itxaka/go-ukify/pkg/measure"
	"github.com/itxaka/go-ukify/pkg/pesign"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log/slog"
	"os"
)

var measureCmd = &cobra.Command{
	Use:   "measure FILE",
	Short: "Measure a single file",
	PreRunE: func(cmd *cobra.Command, args []string) error {
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
		pcr := viper.GetInt("pcr")
		slog.Info("Starting to measure", "file", args[0], "output", output, "pcr-key", key, "pcr", pcr)
		signer, err := pesign.NewPCRSigner(key)
		if err != nil {
			return err
		}

		measurements, err := measure.GenerateSignedPCRForBytes(args[0], signer, pcr)
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
		slog.Info("Finished measuring", "file", args[0], "output", output, "pcr-key", key, "pcr", pcr)
		return nil
	},
}

func init() {
	measureCmd.Flags().StringP("pcr-key", "p", "", "PCR key.")
	measureCmd.Flags().Int("pcr", 0, "TPM PCR to measure against.")
	measureCmd.Flags().StringP("output", "o", "measurements.json", "Output file for measurements in json format.")
	measureCmd.Flags().String("log-level", "info", "Log level.")
	// Set flag as required
	_ = measureCmd.MarkFlagRequired("pcr-key")
	_ = measureCmd.MarkFlagRequired("pcr")
	_ = viper.BindPFlags(measureCmd.Flags())

	rootCmd.AddCommand(measureCmd)

}
