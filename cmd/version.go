package cmd

import (
	"fmt"
	"github.com/itxaka/go-ukify/internal/common"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version",
	RunE: func(cmd *cobra.Command, args []string) error {
		long, _ := cmd.Flags().GetBool("long")
		if long {
			fmt.Printf("%+v\n", common.Get())
		} else {
			fmt.Println(common.GetVersion())
		}
		return nil
	},
}

func init() {
	versionCmd.Flags().BoolP("long", "l", false, "long version format")
	_ = viper.BindPFlags(measureCmd.Flags())
	rootCmd.AddCommand(versionCmd)
}
