package main

import (
	"fmt"
	"github.com/itxaka/go-secureboot/pkg/uki"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
			return err
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// Convert the pr
			builder := &uki.Builder{}
			err := builder.Build(func(s string, a ...any) {
				fmt.Println(s, a)
			})
			return err
		},
	}

	c.Flags().String("arch", "", "Arch of the UKI file.")
	c.Flags().String("version", "", "Version of Talos.")
	c.Flags().String("sd-stub-path", "", "Path to the sd-stub.")
	c.Flags().String("sd-boot-path", "", "Path to the sd-boot.")
	c.Flags().String("kernel-path", "", "Path to the kernel image.")
	c.Flags().String("initrd-path", "", "Path to the initrd image.")
	c.Flags().String("cmdline", "", "Kernel cmdline.")
	c.Flags().String("secure-boot-cert", "", "SecureBoot certificate to sign efi files with.")
	c.Flags().String("pcr-cert", "", "PCR signer.")
	c.Flags().String("out-sd-boot-path", "", "Path to the signed sd-boot.")
	c.Flags().String("out-uki-path", "", "Path to the output UKI file.")

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
