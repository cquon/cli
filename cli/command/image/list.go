package image

import (
	"context"
	"os"
	"fmt"
	"net"
	"time"
	"strings"
	"net/http"
	"io/ioutil"
	"crypto/tls"
	"encoding/json"
	"text/tabwriter"
	"github.com/dustin/go-humanize"

	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/command/formatter"
	"github.com/docker/cli/opts"
	"github.com/docker/docker/api/types"
	"github.com/spf13/cobra"
)

type imagesOptions struct {
	matchName string

	quiet       bool
	all         bool
	noTrunc     bool
	showDigests bool
	remote		bool
	format      string
	filter      opts.FilterOpt
}

// NewImagesCommand creates a new `docker images` command
func NewImagesCommand(dockerCli command.Cli) *cobra.Command {
	options := imagesOptions{filter: opts.NewFilterOpt()}

	cmd := &cobra.Command{
		Use:   "images [OPTIONS] [REPOSITORY[:TAG]]",
		Short: "List local images or remote images in a registry",
		Args:  cli.RequiresMaxArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				options.matchName = args[0]
			}
			showImages(dockerCli, args, options.remote)
			return nil
			//return runImages(dockerCli, options)
		},
	}

	flags := cmd.Flags()

	flags.BoolVarP(&options.quiet, "quiet", "q", false, "Only show numeric IDs")
	flags.BoolVarP(&options.all, "all", "a", false, "Show all images (default hides intermediate images)")
	flags.BoolVar(&options.noTrunc, "no-trunc", false, "Don't truncate output")
	flags.BoolVar(&options.showDigests, "digests", false, "Show digests")
	flags.BoolVar(&options.remote, "remote", false, "Show images from remote registry")
	flags.StringVar(&options.format, "format", "", "Pretty-print images using a Go template")
	flags.VarP(&options.filter, "filter", "f", "Filter output based on conditions provided")

	return cmd
}

func newListCommand(dockerCli command.Cli) *cobra.Command {
	cmd := *NewImagesCommand(dockerCli)
	cmd.Aliases = []string{"images", "list"}
	cmd.Use = "ls [OPTIONS] [REPOSITORY[:TAG]]"
	return &cmd
}

func runImages(dockerCli command.Cli, options imagesOptions) error {
	ctx := context.Background()

	filters := options.filter.Value()
	if options.matchName != "" {
		filters.Add("reference", options.matchName)
	}

	listOptions := types.ImageListOptions{
		All:     options.all,
		Filters: filters,
	}

	images, err := dockerCli.Client().ImageList(ctx, listOptions)
	if err != nil {
		return err
	}

	format := options.format
	if len(format) == 0 {
		if len(dockerCli.ConfigFile().ImagesFormat) > 0 && !options.quiet {
			format = dockerCli.ConfigFile().ImagesFormat
		} else {
			format = formatter.TableFormatKey
		}
	}

	imageCtx := formatter.ImageContext{
		Context: formatter.Context{
			Output: dockerCli.Out(),
			Format: formatter.NewImageFormat(format, options.quiet, options.showDigests),
			Trunc:  !options.noTrunc,
		},
		Digest: options.showDigests,
	}
	return formatter.ImageWrite(imageCtx, images)
}


func showImages(dockerCli command.Cli, args []string, remote bool) {
	if !remote {
		showLocalImages(dockerCli, args)
	} else {
		// XXX - show the remote registries if no registry is specified
		d := getGUNParts(args[0])
		if d.Repository == "" {
			showRemoteRepos(dockerCli, d)
		} else {
			showRemoteImages(dockerCli, d)
		}
	}
}

func showLocalImages(dockerCli command.Cli, args []string) {
	d := getImagesData(args)

	w := tabwriter.NewWriter(os.Stdout, 20, 0, 1, ' ', 0)
	fmt.Fprintln(w, "REPOSITORY\tTAG\tIMAGE ID\tCREATED\tSIZE\tREGISTRY")
	for _, i := range d {
		digests := make(map[string]string)
		if i.RepoDigests != nil {
			for _, rd := range i.RepoDigests {
				td := strings.Split(rd, "@")
				digests[td[0]] = td[1]
			}
		}
		if i.RepoTags != nil {
			id := strings.Split(i.Id, ":")
			s := humanize.Bytes(i.Size)
			ct := humanize.Time(time.Unix(i.Created, 0))
			for _, t := range i.RepoTags {
				reg := ""
				rt := strings.Split(t, ":")
				if rt[0] != "<none>" {
					_, ok := digests[rt[0]]
					if ok {
						if digestExistsInRegistry(dockerCli, rt[0], digests[rt[0]]) {
							reg = "*"
						}
					}
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", rt[0], rt[1], id[1][:12], ct, s, reg)
			}
		}
	}
	w.Flush()
}

func showRemoteImages(dockerCli command.Cli, t TagData) {
	d := getDTRImages(dockerCli, t)

	w := tabwriter.NewWriter(os.Stdout, 20, 0, 1, ' ', 0)
	fmt.Fprintln(w, "REPOSITORY\tTAG\tIMAGE ID\tCREATED\tSIZE")
	repo := t.Hostname + "/" + t.Repository
	for _, i := range d {
		id := strings.Split(i.Id, ":")
		s := humanize.Bytes(i.Manifest.Size)
		tt, _ := time.Parse(time.RFC3339, i.CreatedAt)
		ct := humanize.Time(tt)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", repo, i.Name, id[1][:12], ct, s)
	}
	w.Flush()
}

func showRemoteRepos(dockerCli command.Cli, d TagData) {
	repos := getRepositories(dockerCli, d.Hostname)

	w := tabwriter.NewWriter(os.Stdout, 20, 0, 1, ' ', 0)
	fmt.Fprintln(w, "REPOSITORY\tPUBLIC\tPULLS\tPUSHES")
	for _, i := range repos {
		t := fmt.Sprintf("%s/%s/%s", d.Hostname, i.Namespace, i.Name)
		public := ""
		if i.Visibility == "public" {
			public = "*"
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\n", t, public, i.PullCount, i.PushCount)
	}
	w.Flush()
}

func getImageDataByID(id string) ImageDetailData {
	httpc := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", "/var/run/docker.sock")
			},
		},
	}

	var response *http.Response
	var err error

	response, err = httpc.Get("http://unix" + fmt.Sprintf("/v1.39/images/%s/json", id))
	if err != nil {
		panic(err)
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		panic(err)
	}

	var d ImageDetailData
	err = json.Unmarshal(body, &d)
	if err != nil {
		panic(err)
	}
	return d
}

func getImagesData(args []string) []ImageData {
	httpc := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", "/var/run/docker.sock")
			},
		},
	}

	var response *http.Response
	var err error

	url := "http://unix" + "/v1.39/images/json"
	if len(args) == 1 {
		url = "http://unix" + fmt.Sprintf("/v1.39/images/%s/json", args[0])
	}

	response, err = httpc.Get(url)
	if err != nil {
		panic(err)
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		panic(err)
	}

	var d []ImageData
	if len(args) == 0 {
		err = json.Unmarshal(body, &d)
		if err != nil {
			panic(err)
		}
	} else if len(args) == 1 {
		var imgData ImageDetailData
		err = json.Unmarshal(body, &imgData)
		if err != nil {
			panic(err)
		}
		//d = append(d, ImageData(imgData))
	}
	return d
}

func getRepositories(dockerCli command.Cli, hostname string) []RepositoryData {
	url := fmt.Sprintf("https://%s/api/v0/repositories", hostname)

	var repos RepositoriesData

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
		err = json.Unmarshal(body, &repos)
		if err != nil {
			panic(err)
		}
	}

	return repos.Repositories
}

func getDTRImages(dockerCli command.Cli, t TagData) []DTRImageData {
	url := fmt.Sprintf("https://%s/api/v0/repositories/%s/tags", t.Hostname, t.Repository)

	var tags []DTRImageData

	req, err := http.NewRequest("GET", url, nil)
	registryCfg, err := dockerCli.ConfigFile().GetAuthConfig(t.Hostname)
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
		err = json.Unmarshal(body, &tags)
		if err != nil {
			panic(err)
		}
	}

	return tags
}

func digestExistsInRegistry(dockerCli command.Cli, reponame string, digest string) bool {
	tag := getGUNParts(reponame)
	t := getAuthToken(dockerCli, tag.Hostname, tag.Repository, "")
	return checkManifestExists(tag.Hostname, tag.Repository, digest, t)
}


func getAuthToken(dockerCli command.Cli, hostname string, reponame string, tokentype string) *AuthToken {
	tokenpath := "auth/token"
	service := hostname
	if hostname == "" {
		hostname = "auth.docker.io"
		tokenpath = "token"
	}

	if hostname == "auth.docker.io" {
		service = "registry.docker.io"
	}

	if tokentype == "" {
		tokentype = "pull"
	}

	if !strings.Contains(reponame, "/") {
		reponame = "library/" + reponame
	}

	url := fmt.Sprintf("https://%s/%s?service=%s&scope=repository:%s:%s", hostname, tokenpath, service, reponame, tokentype)

	req, err := http.NewRequest("GET", url, nil)
	if service != "registry.docker.io" {
		registryCfg, _ := dockerCli.ConfigFile().GetAuthConfig(hostname)
		req.SetBasicAuth(registryCfg.Username, registryCfg.IdentityToken)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	httpc := &http.Client{Transport: tr}
	response, err := httpc.Do(req)
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		panic(err)
	}

	var t AuthToken
	err = json.Unmarshal(body, &t)
	if err != nil {
		panic(err)
	}

	return &t
}

func checkManifestExists(hostname string, reponame string, digest string, t *AuthToken) bool {
	if hostname == "" {
		hostname = "registry-1.docker.io"
	}

	if !strings.Contains(reponame, "/") {
		reponame = "library/" + reponame
	}

	url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", hostname, reponame, digest)

	req, err := http.NewRequest("HEAD", url, nil)
	req.Header.Add("Authorization", "Bearer " + t.Token)

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
		return true
	}
	return false
}



type NetworkData struct {
	NetworkID           string
	EndpointID          string
	Gateway             string
	IPAddress           string
	IPPrefixLen         int
	IPv6Gateway         string
	GlobalIPv6Address   string
	GlobalIPv6PrefixLen int
	MacAddress          string
}

type ContainerData struct {
	Id          string
	Names       []string
	Image       string
	ImageID     string
	Command     string
	Created     int64
	Ports       []PortData
	Labels      map[string]string
	State       string
	Status      string
	HostConfig  map[string]string
	Networks    map[string]NetworkData
}

type PortData struct {
	IP          string
	PrivatePort int
	PublicPort  int
	Type        string
}

type ImageData struct {
	Containers  int
	Created     int64
	Id          string
	ParentId    string
	SharedSize  int
	Size        uint64
	VirtualSize int
	RepoTags    []string
	RepoDigests []string
}

type ImageDetailData struct {
	Id          string
	RepoTags    []string
	RepoDigests []string
	//Created     string // XXX - why is this different than ImageData.Created?
	// ... and more
}

type AuthToken struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
	Expires     int    `json:"expires"`
	IssuedAt    string `json:"issued_at"`
}

type TagData struct {
	Hostname   string
	Namespace  string
	Repository string
	Tag        string
}

type RepositoriesData struct {
	Repositories []RepositoryData `json:"repositories"`
}

type RepositoryData struct {
	Id            string `json:"id"`
	Namespace     string `json:"namespace"`
	NamespaceType string `json:"namespaceType"`
	Name          string `json:"name"`
	ShortText     string `json:"shortDescription"`
	Visibility    string `json:"visibility"`
	ScanOnPush    bool   `json:"scanOnPush"`
	ImmutableTags bool   `json:"immutableTags"`
	ManifestLists bool   `json:"enableManifestLists"`
	PullCount     int    `json:"pulls"`
	PushCount     int    `json:"pushes"`
	TagLimit      int    `json:"tagLimit"`
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
