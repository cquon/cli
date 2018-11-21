package registry

import (
	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/command/formatter"
	"github.com/docker/cli/opts"
	"github.com/spf13/cobra"
)

type registryOptions struct {
	matchName string

	quiet       bool
	all         bool
	noTrunc     bool
	showDigests bool
	format      string
	filter      opts.FilterOpt
}

// newListCommand creates a new `docker registry` command
func newListCommand(dockerCli command.Cli) *cobra.Command {
	options := registryOptions{filter: opts.NewFilterOpt()}

	cmd := &cobra.Command{
		Use:   "ls [OPTIONS] [REPOSITORY[:TAG]]",
		Short: "List registries",
		Args:  cli.RequiresMaxArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				options.matchName = args[0]
			}
			return runListRegistries(dockerCli, options)
		},
	}
/*
	flags := cmd.Flags()

	flags.BoolVarP(&options.quiet, "quiet", "q", false, "Only show numeric IDs")
	flags.BoolVarP(&options.all, "all", "a", false, "Show all images (default hides intermediate images)")
	flags.BoolVar(&options.noTrunc, "no-trunc", false, "Don't truncate output")
	flags.BoolVar(&options.showDigests, "digests", false, "Show digests")
	flags.StringVar(&options.format, "format", "", "Pretty-print images using a Go template")
	flags.VarP(&options.filter, "filter", "f", "Filter output based on conditions provided")
*/
	return cmd
}

func runListRegistries(dockerCli command.Cli, options registryOptions) error {
	//ctx := context.Background()

	filters := options.filter.Value()
	if options.matchName != "" {
		filters.Add("reference", options.matchName)
	}

	var registries []string
	for registry, _ := range dockerCli.ConfigFile().AuthConfigs {
		registries = append(registries, registry)
	}

	format := formatter.TableFormatKey

	registryCtx := formatter.Context{
		Output: dockerCli.Out(),
		Format: formatter.NewRegistryFormat(format, options.quiet),
	}
	return formatter.RegistryWrite(registryCtx, registries)
}
