package cmd

import (
	"github.com/kairos-io/go-ukify/pkg/pesign"
	"github.com/kairos-io/go-ukify/pkg/uki"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var createUkify = &cobra.Command{
	Use:   "create",
	Short: "Create a uki file",
	RunE: func(cmd *cobra.Command, args []string) error {
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

func init() {
	createUkify.Flags().StringP("arch", "a", "", "Arch of the UKI file.")
	createUkify.Flags().String("version", "", "Version.")
	createUkify.Flags().StringP("sd-stub-path", "s", "", "Path to the sd-stub.")
	createUkify.Flags().StringP("sd-boot-path", "b", "", "Path to the sd-boot.")
	createUkify.Flags().StringP("kernel-path", "k", "", "Path to the kernel image.")
	createUkify.Flags().StringP("initrd-path", "i", "", "Path to the initrd image.")
	createUkify.Flags().StringP("cmdline", "c", "", "Kernel cmdline.")
	createUkify.Flags().StringP("os-release", "o", "", "os-release file.")
	createUkify.Flags().String("sb-cert", "", "SecureBoot certificate to sign efi files with.")
	createUkify.Flags().String("sb-key", "", "SecureBoot certificate to sign efi files with.")
	createUkify.Flags().StringP("pcr-key", "p", "", "PCR key.")
	createUkify.Flags().StringP("output-sdboot", "", "sdboot.signed.efi", "sdboot output.")
	createUkify.Flags().StringP("output-uki", "", "uki.signed.efi", "uki artifact output.")

	_ = createUkify.MarkFlagRequired("sd-stub-path")
	_ = createUkify.MarkFlagRequired("sd-boot-path")
	_ = createUkify.MarkFlagRequired("initrd-path")
	_ = createUkify.MarkFlagRequired("pcr-key")
	_ = viper.BindPFlags(measureCmd.Flags())

	rootCmd.AddCommand(createUkify)

}
