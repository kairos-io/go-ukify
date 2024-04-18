package main

import (
	"fmt"
	"github.com/itxaka/go-secureboot/pkg/pesign"
	"github.com/itxaka/go-secureboot/pkg/uki"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log/slog"
	"os"
)

func main() {
	c := cobra.Command{
		Use: "ukify",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			if viper.GetString("sd-stub-path") == "" {
				return fmt.Errorf("sd-stub-path is required")
			}
			if viper.GetString("sd-boot-path") == "" {
				return fmt.Errorf("sd-boot-path is required")
			}
			if viper.GetString("kernel-path") == "" {
				return fmt.Errorf("kernel-path is required")
			}
			if viper.GetString("initrd-path") == "" {
				return fmt.Errorf("initrd-path is required")
			}
			if viper.GetString("pcr-key") == "" {
				return fmt.Errorf("pcr-key is required")
			}
			return err
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			slog.SetLogLoggerLevel(slog.LevelDebug)
			signer, err := pesign.NewPCRSigner(viper.GetString("pcr-key"))
			if err != nil {
				return err
			}
			sbSigner, err := pesign.NewSecureBootSigner(viper.GetString("sb-cert"), viper.GetString("sb-key"))
			if err != nil {
				return err
			}
			builder := &uki.Builder{
				Arch:             viper.GetString("arch"),
				Version:          viper.GetString("version"),
				SdStubPath:       viper.GetString("sd-stub-path"),
				SdBootPath:       viper.GetString("sd-boot-path"),
				KernelPath:       viper.GetString("kernel-path"),
				InitrdPath:       viper.GetString("initrd-path"),
				Cmdline:          viper.GetString("cmdline"),
				OutSdBootPath:    viper.GetString("output-sdboot"),
				OutUKIPath:       viper.GetString("output-uki"),
				PCRSigner:        signer,
				SecureBootSigner: sbSigner,
			}

			if viper.GetString("os-release") != "" {
				builder.OsRelease = viper.GetString("os-release")
			}

			return builder.Build()
		},
	}

	c.Flags().StringP("arch", "a", "", "Arch of the UKI file.")
	c.Flags().String("version", "", "Version.")
	c.Flags().StringP("sd-stub-path", "s", "", "Path to the sd-stub.")
	c.Flags().StringP("sd-boot-path", "b", "", "Path to the sd-boot.")
	c.Flags().StringP("kernel-path", "k", "", "Path to the kernel image.")
	c.Flags().StringP("initrd-path", "i", "", "Path to the initrd image.")
	c.Flags().StringP("cmdline", "c", "", "Kernel cmdline.")
	c.Flags().StringP("os-release", "o", "", "os-release file.")
	c.Flags().String("sb-cert", "", "SecureBoot certificate to sign efi files with.")
	c.Flags().String("sb-key", "", "SecureBoot certificate to sign efi files with.")
	c.Flags().StringP("pcr-key", "p", "", "PCR key.")
	c.Flags().StringP("output-sdboot", "", "sdboot.signed.efi", "sdboot output.")
	c.Flags().StringP("output-uki", "", "uki.signed.efi", "uki artifact output.")

	err := viper.BindPFlags(c.Flags())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if err := c.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
