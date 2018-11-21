package formatter

const (
	defaultRegistryQuietFormat = "{{.Registry}}"
	defaultRegistryTableFormat = "table {{.Registry}}"

	registryHeader = "REGISTRY"
)

// NewRegistryFormat returns a format for use with a Registry Context
func NewRegistryFormat(source string, quiet bool) Format {
	switch source {
	case TableFormatKey:
		if quiet {
			return defaultRegistryQuietFormat
		}
		return defaultRegistryTableFormat
	case RawFormatKey:
		if quiet {
			return `registry: {{.Registry}}`
		}
		return `registry: {{.Registry}}\n`
	}
	return Format(source)
}

// RegistryWrite writes formatted volumes using the Context
func RegistryWrite(ctx Context, registries []string) error {
	render := func(format func(subContext SubContext) error) error {
		for _, registry := range registries {
			if err := format(&registryContext{r: registry}); err != nil {
				return err
			}
		}
		return nil
	}
	return ctx.Write(newRegistryContext(), render)
}

type registryContext struct {
	HeaderContext
	r string
}

func newRegistryContext() *registryContext {
	registryCtx := registryContext{}
	registryCtx.Header = SubHeaderContext{
		"Registry":       registryHeader,
	}
	return &registryCtx
}

func (c *registryContext) MarshalJSON() ([]byte, error) {
	return MarshalJSON(c)
}

func (c *registryContext) Registry() string {
	return c.r
}
