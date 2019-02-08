package image

import (
	"context"
	"os"
	"fmt"
	"time"
	"io/ioutil"
	"encoding/json"
	"net/http"
	"strings"
	"crypto/tls"
	"text/tabwriter"

	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/command/formatter"
	"github.com/spf13/cobra"
	"github.com/dustin/go-humanize"
)

type historyOptions struct {
	image string

	human   bool
	quiet   bool
	noTrunc bool
	remote bool
	format  string
}

// NewHistoryCommand creates a new `docker history` command
func NewHistoryCommand(dockerCli command.Cli) *cobra.Command {
	var opts historyOptions

	cmd := &cobra.Command{
		Use:   "history [OPTIONS] IMAGE",
		Short: "Show the history of an image",
		Args:  cli.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.image = args[0]
			if opts.remote {
				showRemoteHistory(dockerCli, args)
				return nil
			}
			return runHistory(dockerCli, opts)
		},
	}

	flags := cmd.Flags()

	flags.BoolVarP(&opts.human, "human", "H", true, "Print sizes and dates in human readable format")
	flags.BoolVarP(&opts.quiet, "quiet", "q", false, "Only show numeric IDs")
	flags.BoolVar(&opts.noTrunc, "no-trunc", false, "Don't truncate output")
	flags.BoolVar(&opts.remote, "remote", false, "Get history of image from remote registry")
	flags.StringVar(&opts.format, "format", "", "Pretty-print images using a Go template")

	return cmd
}

func runHistory(dockerCli command.Cli, opts historyOptions) error {
	ctx := context.Background()

	history, err := dockerCli.Client().ImageHistory(ctx, opts.image)
	if err != nil {
		return err
	}

	format := opts.format
	if len(format) == 0 {
		format = formatter.TableFormatKey
	}

	historyCtx := formatter.Context{
		Output: dockerCli.Out(),
		Format: NewHistoryFormat(format, opts.quiet, opts.human),
		Trunc:  !opts.noTrunc,
	}
	return HistoryWrite(historyCtx, opts.human, history)
}



func showRemoteHistory(dockerCli command.Cli, args []string) {
	// do the things
	tag := getGUNParts(args[0])
	showHistoryCommands(dockerCli, tag)
}

func showHistoryCommands(dockerCli command.Cli, tag TagData) {
	d, _ := getManifest(dockerCli, tag.Hostname, tag.Repository, tag.Tag)

	w := tabwriter.NewWriter(os.Stdout, 20, 0, 1, ' ', 0)
	fmt.Fprintln(w, "IMAGE\tCREATED\tCREATED BY\tSIZE (COMPRESSED)\tCOMMENT")

	for i := len(d.Dockerfile)-1; i >= 0; i-- {
		l := d.Dockerfile[i].Line
		if len(l) > 45 {
			l = l[:44] + "..."
		}
		tt, _ := time.Parse(time.RFC3339, d.CreatedAt)
		ct := humanize.Time(tt)
		if i == len(d.Dockerfile)-1 {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t\n", d.Digest[7:19], ct, l, humanize.Bytes(d.Dockerfile[i].Size))
		} else {
			fmt.Fprintf(w, "<missing>\t%s\t%s\t%s\t\n", ct, l, humanize.Bytes(d.Dockerfile[i].Size))
		}
	}
	w.Flush()
}


func getManifest(dockerCli command.Cli, hostname string, reponame string, digest string) (*DTRImageManifest, string) {
	if hostname == "" {
		hostname = "registry-1.docker.io"
	}

	if !strings.Contains(reponame, "/") {
		reponame = "library/" + reponame
	}

	url := fmt.Sprintf("https://%s/api/v0/repositories/%s/tags/%s", hostname, reponame, digest)

	// For pulling directly from registry
	// url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", hostname, reponame, digest)

	req, err := http.NewRequest("GET", url, nil)
	registryCfg, err := dockerCli.ConfigFile().GetAuthConfig(hostname)
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

	if response.StatusCode == 200 {
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			panic(err)
		}
		var manifests []DTRImageData
		err = json.Unmarshal(body, &manifests)
		if err != nil {
			panic(err)
		}
		return &manifests[0].Manifest, string(body)
	}
	return nil, ""
}

