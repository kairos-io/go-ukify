package cmd

import (
	"github.com/kairos-io/go-ukify/pkg/constants"
	"github.com/kairos-io/go-ukify/pkg/types"
	"github.com/kairos-io/go-ukify/pkg/uki"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log/slog"
	"strings"
)

var createUkify = &cobra.Command{
	Use:   "create",
	Short: "Create a uki file",
	RunE: func(cmd *cobra.Command, args []string) error {
		var parsedPhases []types.PhaseInfo

		phases := viper.GetString("phases")
		// Default to know systemd phases
		if phases == "" {
			parsedPhases = types.OrderedPhases()
		} else {
			// Parse phases from string in order
			for _, phase := range strings.Split(phases, ":") {
				parsedPhases = append(parsedPhases, types.PhaseInfo{Phase: constants.Phase(phase)})
			}
		}

		if viper.GetBool("debug") {
			slog.SetLogLoggerLevel(slog.LevelDebug)
		}

		builder := &uki.Builder{
			Arch:          viper.GetString("arch"),
			Version:       viper.GetString("version"),
			SdStubPath:    viper.GetString("sd-stub-path"),
			SdBootPath:    viper.GetString("sd-boot-path"),
			KernelPath:    viper.GetString("kernel"),
			InitrdPath:    viper.GetString("initrd"),
			Cmdline:       viper.GetString("cmdline"),
			OutSdBootPath: viper.GetString("output-sdboot"),
			OutUKIPath:    viper.GetString("output-uki"),
			PCRKey:        viper.GetString("pcr-key"),
			SBKey:         viper.GetString("sb-key"),
			SBCert:        viper.GetString("sb-cert"),
			Splash:        viper.GetString("splash"),
			Phases:        parsedPhases,
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
	createUkify.Flags().StringP("kernel", "k", "", "Path to the kernel image.")
	createUkify.Flags().StringP("initrd", "i", "", "Path to the initrd image.")
	createUkify.Flags().StringP("cmdline", "c", "", "Kernel cmdline.")
	createUkify.Flags().StringP("os-release", "o", "", "os-release file.")
	createUkify.Flags().String("sb-cert", "", "SecureBoot certificate to sign efi files with.")
	createUkify.Flags().String("sb-key", "", "SecureBoot certificate to sign efi files with.")
	createUkify.Flags().StringP("pcr-key", "p", "", "PCR key.")
	createUkify.Flags().StringP("output-sdboot", "", "sdboot.signed.efi", "sdboot output.")
	createUkify.Flags().StringP("output-uki", "", "uki.signed.efi", "uki artifact output.")
	createUkify.Flags().StringP("phases", "", "enter-initrd:leave-initrd:sysinit:ready", "phases to measure for, separated by : and in order of measurement")
	createUkify.Flags().String("splash", "", "Path to the custom logo splash BMP file.")
	createUkify.Flags().Bool("debug", false, "Enable debug output")

	_ = createUkify.MarkFlagRequired("sd-stub-path")
	_ = createUkify.MarkFlagRequired("initrd")
	_ = createUkify.MarkFlagRequired("kernel")
	_ = viper.BindPFlags(createUkify.Flags())

	rootCmd.AddCommand(createUkify)

}
