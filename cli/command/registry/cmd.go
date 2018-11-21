package registry

import (
	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/spf13/cobra"
)

// NewNodeCommand returns a cobra command for `registry` subcommands
func NewRegistryCommand(dockerCli command.Cli) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "registry",
		Short: "Manage Registries",
		Args:  cli.NoArgs,
		RunE:  command.ShowHelp(dockerCli.Err()),
	}
	cmd.AddCommand(
		newListCommand(dockerCli),
	)
	return cmd
}
