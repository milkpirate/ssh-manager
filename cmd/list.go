package cmd

import (
	"fmt"

	"github.com/omegion/ssh-manager/internal/provider"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// setupListCommand sets default flags.
func setupListCommand(cmd *cobra.Command) {
	cmd.Flags().String("provider", "", "Provider")

	if err := cmd.MarkFlagRequired("provider"); err != nil {
		log.Fatalf("Lethal damage: %s\n\n", err)
	}
}

// List acquires SSH keys from given provider.
func List() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List SSH keys from given provider.",
		RunE: func(cmd *cobra.Command, args []string) error {
			providerName, _ := cmd.Flags().GetString("provider")

			commander := provider.NewCommander()

			prv, err := decideProvider(&providerName, &commander)
			if err != nil {
				return err
			}

			items, err := prv.List()
			if err != nil {
				return err
			}

			log.Infoln("SSH Keys are fetched.")

			for _, item := range items {
				fmt.Println(item.Name)
			}

			return nil
		},
	}

	setupListCommand(cmd)

	return cmd
}
