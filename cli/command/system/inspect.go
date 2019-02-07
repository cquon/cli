package system

import (
	"context"
	"fmt"
	"strings"
	"net/http"
	"io/ioutil"
	"crypto/tls"
	"encoding/json"

	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/command/inspect"
	"github.com/docker/docker/api/types"
	apiclient "github.com/docker/docker/client"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type inspectOptions struct {
	format      string
	inspectType string
	size        bool
	remote		bool
	ids         []string
}

// NewInspectCommand creates a new cobra.Command for `docker inspect`
func NewInspectCommand(dockerCli command.Cli) *cobra.Command {
	var opts inspectOptions

	cmd := &cobra.Command{
		Use:   "inspect [OPTIONS] NAME|ID [NAME|ID...]",
		Short: "Return low-level information on local or remote Docker objects",
		Args:  cli.RequiresMinArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.ids = args
			if opts.remote {
				inspectRegistryImage(dockerCli, args)
				return nil
			} else {
				return runInspect(dockerCli, opts)
			}
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&opts.format, "format", "f", "", "Format the output using the given Go template")
	flags.StringVar(&opts.inspectType, "type", "", "Return JSON for specified type")
	flags.BoolVarP(&opts.size, "size", "s", false, "Display total file sizes if the type is container")
	flags.BoolVar(&opts.remote, "remote", false, "Display image information on a remote Registry object")

	return cmd
}

func runInspect(dockerCli command.Cli, opts inspectOptions) error {
	var elementSearcher inspect.GetRefFunc
	switch opts.inspectType {
	case "", "container", "image", "node", "network", "service", "volume", "task", "plugin", "secret":
		elementSearcher = inspectAll(context.Background(), dockerCli, opts.size, opts.inspectType)
	default:
		return errors.Errorf("%q is not a valid value for --type", opts.inspectType)
	}
	return inspect.Inspect(dockerCli.Out(), opts.ids, opts.format, elementSearcher)
}

func inspectContainers(ctx context.Context, dockerCli command.Cli, getSize bool) inspect.GetRefFunc {
	return func(ref string) (interface{}, []byte, error) {
		return dockerCli.Client().ContainerInspectWithRaw(ctx, ref, getSize)
	}
}

func inspectImages(ctx context.Context, dockerCli command.Cli) inspect.GetRefFunc {
	return func(ref string) (interface{}, []byte, error) {
		return dockerCli.Client().ImageInspectWithRaw(ctx, ref)
	}
}

func inspectNetwork(ctx context.Context, dockerCli command.Cli) inspect.GetRefFunc {
	return func(ref string) (interface{}, []byte, error) {
		return dockerCli.Client().NetworkInspectWithRaw(ctx, ref, types.NetworkInspectOptions{})
	}
}

func inspectNode(ctx context.Context, dockerCli command.Cli) inspect.GetRefFunc {
	return func(ref string) (interface{}, []byte, error) {
		return dockerCli.Client().NodeInspectWithRaw(ctx, ref)
	}
}

func inspectService(ctx context.Context, dockerCli command.Cli) inspect.GetRefFunc {
	return func(ref string) (interface{}, []byte, error) {
		// Service inspect shows defaults values in empty fields.
		return dockerCli.Client().ServiceInspectWithRaw(ctx, ref, types.ServiceInspectOptions{InsertDefaults: true})
	}
}

func inspectTasks(ctx context.Context, dockerCli command.Cli) inspect.GetRefFunc {
	return func(ref string) (interface{}, []byte, error) {
		return dockerCli.Client().TaskInspectWithRaw(ctx, ref)
	}
}

func inspectVolume(ctx context.Context, dockerCli command.Cli) inspect.GetRefFunc {
	return func(ref string) (interface{}, []byte, error) {
		return dockerCli.Client().VolumeInspectWithRaw(ctx, ref)
	}
}

func inspectPlugin(ctx context.Context, dockerCli command.Cli) inspect.GetRefFunc {
	return func(ref string) (interface{}, []byte, error) {
		return dockerCli.Client().PluginInspectWithRaw(ctx, ref)
	}
}

func inspectSecret(ctx context.Context, dockerCli command.Cli) inspect.GetRefFunc {
	return func(ref string) (interface{}, []byte, error) {
		return dockerCli.Client().SecretInspectWithRaw(ctx, ref)
	}
}

func inspectAll(ctx context.Context, dockerCli command.Cli, getSize bool, typeConstraint string) inspect.GetRefFunc {
	var inspectAutodetect = []struct {
		objectType      string
		isSizeSupported bool
		isSwarmObject   bool
		objectInspector func(string) (interface{}, []byte, error)
	}{
		{
			objectType:      "container",
			isSizeSupported: true,
			objectInspector: inspectContainers(ctx, dockerCli, getSize),
		},
		{
			objectType:      "image",
			objectInspector: inspectImages(ctx, dockerCli),
		},
		{
			objectType:      "network",
			objectInspector: inspectNetwork(ctx, dockerCli),
		},
		{
			objectType:      "volume",
			objectInspector: inspectVolume(ctx, dockerCli),
		},
		{
			objectType:      "service",
			isSwarmObject:   true,
			objectInspector: inspectService(ctx, dockerCli),
		},
		{
			objectType:      "task",
			isSwarmObject:   true,
			objectInspector: inspectTasks(ctx, dockerCli),
		},
		{
			objectType:      "node",
			isSwarmObject:   true,
			objectInspector: inspectNode(ctx, dockerCli),
		},
		{
			objectType:      "plugin",
			objectInspector: inspectPlugin(ctx, dockerCli),
		},
		{
			objectType:      "secret",
			isSwarmObject:   true,
			objectInspector: inspectSecret(ctx, dockerCli),
		},
	}

	// isSwarmManager does an Info API call to verify that the daemon is
	// a swarm manager.
	isSwarmManager := func() bool {
		info, err := dockerCli.Client().Info(ctx)
		if err != nil {
			fmt.Fprintln(dockerCli.Err(), err)
			return false
		}
		return info.Swarm.ControlAvailable
	}

	return func(ref string) (interface{}, []byte, error) {
		const (
			swarmSupportUnknown = iota
			swarmSupported
			swarmUnsupported
		)

		isSwarmSupported := swarmSupportUnknown

		for _, inspectData := range inspectAutodetect {
			if typeConstraint != "" && inspectData.objectType != typeConstraint {
				continue
			}
			if typeConstraint == "" && inspectData.isSwarmObject {
				if isSwarmSupported == swarmSupportUnknown {
					if isSwarmManager() {
						isSwarmSupported = swarmSupported
					} else {
						isSwarmSupported = swarmUnsupported
					}
				}
				if isSwarmSupported == swarmUnsupported {
					continue
				}
			}
			v, raw, err := inspectData.objectInspector(ref)
			if err != nil {
				if typeConstraint == "" && isErrSkippable(err) {
					continue
				}
				return v, raw, err
			}
			if getSize && !inspectData.isSizeSupported {
				fmt.Fprintf(dockerCli.Err(), "WARNING: --size ignored for %s\n", inspectData.objectType)
			}
			return v, raw, err
		}
		return nil, nil, errors.Errorf("Error: No such object: %s", ref)
	}
}

func isErrSkippable(err error) bool {
	return apiclient.IsErrNotFound(err) ||
		strings.Contains(err.Error(), "not supported") ||
		strings.Contains(err.Error(), "invalid reference format")
}



func inspectRegistryImage(dockerCli command.Cli, args []string) {
	tag := getGUNParts(args[0])
	_, s := getManifest(dockerCli, tag.Hostname, tag.Repository, tag.Tag)
	fmt.Println(s)
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

type TagData struct {
	Hostname   string
	Namespace  string
	Repository string
	Tag        string
}

type DTRImageData struct {
	Id        string `json:"digest"`
	Name      string `json:"name"`
	AuthorId  string `json:"author"`
	UpdatedAt string `json:"updatedAt"`
	CreatedAt string `json:"createdAt"`
	Manifest  DTRImageManifest `json:"manifest"`
}

type DTRImageManifest struct {
	Id              string `json:"digest"`
	Digest          string `json:"configDigest"`
	MediaType       string `json:"mediaType"`
	ConfigMediaType string `json:"configMediaType"`
	Size		uint64 `json:"size"`
	CreatedAt       string `json:"createdAt"`
	Dockerfile      []DTRDockerfileEntry `json:"dockerfile"`
}
type DTRDockerfileEntry struct {
	Line      string `json:"line"`
	Digest    string `json:"layerDigest"`
	Size      uint64 `json:"size"`
	MediaType string `json:"mediaType"`
	IsEmpty   bool `json:"isEmpty"`
}