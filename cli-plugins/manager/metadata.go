package manager

const (
	// NamePrefix is the prefix required on all plugin binary names
	NamePrefix = "docker-"

	// MetadataSubcommandName is the name of the plugin subcommand
	// which must be supported by every plugin and returns the
	// plugin metadata.
	MetadataSubcommandName = "docker-cli-plugin-metadata"
)

// Metadata provided by the plugin
type Metadata struct {
	SchemaVersion    string `json:",omitempty"`
	Version          string `json:",omitempty"`
	Vendor           string `json:",omitempty"`
	ShortDescription string `json:",omitempty"`
	URL              string `json:",omitempty"`
}
