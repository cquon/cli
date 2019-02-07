package image

import (
	"context"
	"fmt"
	"bytes"
	"net/http"
	"crypto/tls"

	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/spf13/cobra"
)

type tagOptions struct {
	image string
	name  string
	remote bool
}

// NewTagCommand creates a new `docker tag` command
func NewTagCommand(dockerCli command.Cli) *cobra.Command {
	var opts tagOptions

	cmd := &cobra.Command{
		Use:   "tag [OPTIONS] SOURCE_IMAGE[:TAG] TARGET_IMAGE[:TAG]",
		Short: "Create a local or remote tag TARGET_IMAGE that refers to SOURCE_IMAGE",
		Args:  cli.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.remote {
				tagRemoteImages(dockerCli, args)
				return nil
			} else {
				opts.image = args[0]
				opts.name = args[1]
				return runTag(dockerCli, opts)
			}
		},
	}

	flags := cmd.Flags()
	flags.SetInterspersed(false)
	flags.BoolVar(&opts.remote, "remote", false, "Show images from remote registry")

	return cmd
}

func runTag(dockerCli command.Cli, opts tagOptions) error {
	ctx := context.Background()

	return dockerCli.Client().ImageTag(ctx, opts.image, opts.name)
}


func tagRemoteImages(dockerCli command.Cli, args []string) {
	stag := getGUNParts(args[0])
	ttag := getGUNParts(args[1])

	if ttag.Hostname == stag.Hostname {
		promoteTag(dockerCli, ttag, stag)
	} else {
		mirrorTag(dockerCli, ttag, stag)
	}
}

func promoteTag(dockerCli command.Cli, targetTag TagData, sourceTag TagData) {
	url := fmt.Sprintf("https://%s/api/v0/repositories/%s/tags/%s/promotion", sourceTag.Hostname, sourceTag.Repository, sourceTag.Tag)

	reqStr := fmt.Sprintf(`{"targetRepository": "%s", "targetTag": "%s"}`, targetTag.Repository, targetTag.Tag)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(reqStr)))
	registryCfg, _ := dockerCli.ConfigFile().GetAuthConfig(targetTag.Hostname)
	req.SetBasicAuth(registryCfg.Username, registryCfg.IdentityToken)
	req.Header.Set("Content-Type", "application/json")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	httpc := &http.Client{Transport: tr}
	response, err := httpc.Do(req)
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()

	if response.StatusCode != 201 {
		fmt.Printf("Couldn't tag image: %s\n", response.Status)
	}

	// XXX - should this also retag the local cache version?
}

func mirrorTag(dockerCli command.Cli, sourceTag TagData, targetTag TagData) {
	url := fmt.Sprintf("https://%s/api/v0/repositories/%s/tags/%s/pushMirroring", sourceTag.Hostname, sourceTag.Repository, sourceTag.Tag)

	targetRegistryCfg, _ := dockerCli.ConfigFile().GetAuthConfig(sourceTag.Hostname)

	reqStr := fmt.Sprintf(`
	{"remoteHost": "%s",
	 "remoteRepository": "%s",
	  "remoteTag": "%s",
	  "username": "%s",
	  "authToken": "%s",
	  "skipTLSVerification: true}`, targetTag.Hostname, targetTag.Repository, targetTag.Tag, targetRegistryCfg.Username, targetRegistryCfg.IdentityToken)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(reqStr)))
	registryCfg, _ := dockerCli.ConfigFile().GetAuthConfig(sourceTag.Hostname)
	req.SetBasicAuth(registryCfg.Username, registryCfg.IdentityToken)
	req.Header.Set("Content-Type", "application/json")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	httpc := &http.Client{Transport: tr}
	response, err := httpc.Do(req)
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()

	if response.StatusCode != 201 {
		fmt.Printf("Couldn't tag image: %s\n", response.Status)
	}

	// XXX - should this also retag the local cache version?
}
