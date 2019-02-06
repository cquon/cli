package image

import (
	"context"
	"fmt"
	"strings"
	"net/http"
	"crypto/tls"

	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/docker/api/types"
	apiclient "github.com/docker/docker/client"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type removeOptions struct {
	force   bool
	remote bool
	noPrune bool
}

// NewRemoveCommand creates a new `docker remove` command
func NewRemoveCommand(dockerCli command.Cli) *cobra.Command {
	var opts removeOptions

	cmd := &cobra.Command{
		Use:   "rmi [OPTIONS] IMAGE [IMAGE...]",
		Short: "Remove one or more local or remote images",
		Args:  cli.RequiresMinArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemove(dockerCli, opts, args)
		},
	}

	flags := cmd.Flags()

	flags.BoolVarP(&opts.force, "force", "f", false, "Force removal of the image")
	flags.BoolVar(&opts.noPrune, "no-prune", false, "Do not delete untagged parents")
	flags.BoolVar(&opts.remote, "remote", false, "Remove image from remote registry.")

	return cmd
}

func newRemoveCommand(dockerCli command.Cli) *cobra.Command {
	cmd := *NewRemoveCommand(dockerCli)
	cmd.Aliases = []string{"rmi", "remove"}
	cmd.Use = "rm [OPTIONS] IMAGE [IMAGE...]"
	return &cmd
}

func runRemove(dockerCli command.Cli, opts removeOptions, images []string) error {

	if opts.remote {
		rmRemoteImages(dockerCli, images, true)
		return nil
	}

	client := dockerCli.Client()
	ctx := context.Background()

	options := types.ImageRemoveOptions{
		Force:         opts.force,
		PruneChildren: !opts.noPrune,
	}

	var errs []string
	var fatalErr = false
	for _, img := range images {
		dels, err := client.ImageRemove(ctx, img, options)
		if err != nil {
			if !apiclient.IsErrNotFound(err) {
				fatalErr = true
			}
			errs = append(errs, err.Error())
		} else {
			for _, del := range dels {
				if del.Deleted != "" {
					fmt.Fprintf(dockerCli.Out(), "Deleted: %s\n", del.Deleted)
				} else {
					fmt.Fprintf(dockerCli.Out(), "Untagged: %s\n", del.Untagged)
				}
			}
		}
	}

	if len(errs) > 0 {
		msg := strings.Join(errs, "\n")
		if !opts.force || fatalErr {
			return errors.New(msg)
		}
		fmt.Fprintln(dockerCli.Err(), msg)
	}
	return nil
}


func rmRemoteImages(dockerCli command.Cli, args []string, remote bool) {
	for _, t := range args {
		tag := getGUNParts(t)
		rmTag(dockerCli, tag)
	}
}

func rmTag(dockerCli command.Cli, targetTag TagData) {
	url := fmt.Sprintf("https://%s/api/v0/repositories/%s/tags/%s", targetTag.Hostname, targetTag.Repository, targetTag.Tag)

	req, err := http.NewRequest("DELETE", url, nil)
	registryCfg, err := dockerCli.ConfigFile().GetAuthConfig(targetTag.Hostname)
	req.SetBasicAuth(registryCfg.Username, registryCfg.IdentityToken)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	httpc := &http.Client{Transport: tr}
	response, err := httpc.Do(req)
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()

	if response.StatusCode == 204 {
		fmt.Printf("Untagged remote: %s/%s:%s\n", targetTag.Hostname, targetTag.Repository, targetTag.Tag)
	} else if response.StatusCode == 404 {
		fmt.Printf("Error: No such image: %s/%s:%s\n", targetTag.Hostname, targetTag.Repository, targetTag.Tag)
	} else {
		fmt.Printf("Couldn't untag image: %s\n", response.Status)
	}
}


func getGUNParts(reponame string) TagData {
	var tag TagData

	// Valid forms:
	//	<hostname>/<namespace>/<repo>:<tag>
	//	<hostname>/<namespace>/<repo>
	//	<namespace>/<repo>:<tag>            Defaults to Hub
	//	<namespace>/<repo>                  Defaults to Hub
	//	<hostname with dots>/<namespace>
	//	<repo>:<tag>                        Defaults to Hub Official repo
	//	<repo>                              Defaults to Hub Official repo
	//	<hostname with dots>

	tp := strings.Split(reponame, ":")
	if len(tp) > 1 {
		tag.Tag = tp[1]
	}

	s := strings.Split(tp[0], "/")
	if len(s) == 1 {
		if strings.ContainsRune(s[0], '.') {
			tag.Hostname = s[0]
		} else {
			tag.Repository = s[0]
		}
	} else if  len(s) == 2 {
		if len(tp) == 1 && strings.ContainsRune(s[0], '.') {
			tag.Hostname = s[0]
			tag.Repository = s[1]
		} else {
			tag.Repository = tp[0]
		}
	} else if len(s) == 3 {
		tag.Hostname = s[0]
		tag.Repository = s[1] + "/" + s[2]
	}
	return tag
}
