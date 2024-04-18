package constants

import (
	"bytes"
	"strings"
	"text/template"
)

const (
	// SignatureKeyAsset defines a well known name for the signature key filename used for auto-enrolling.
	SignatureKeyAsset = "db.auth"

	// PlatformKeyAsset defines a well known name for the platform key filename used for auto-enrolling.
	PlatformKeyAsset = "PK.auth"

	// KeyExchangeKeyAsset defines a well known name for the key exchange key filename used for auto-enrolling.
	KeyExchangeKeyAsset = "KEK.auth"

	PEMTypeRSAPublic = "PUBLIC KEY"
)

const OSReleaseTemplate = `NAME="{{ .Name }}"
ID={{ .ID }}
VERSION_ID={{ .Version }}
PRETTY_NAME="{{ .Name }} ({{ .Version }})"
`

const Name = "NoName"

// OSReleaseFor returns the contents of /etc/os-release for a given name and version.
func OSReleaseFor(name, version string) ([]byte, error) {
	data := struct {
		Name    string
		ID      string
		Version string
	}{
		Name:    name,
		ID:      strings.ToLower(name),
		Version: version,
	}

	tmpl, err := template.New("").Parse(OSReleaseTemplate)
	if err != nil {
		return nil, err
	}

	var writer bytes.Buffer

	err = tmpl.Execute(&writer, data)
	if err != nil {
		return nil, err
	}

	return writer.Bytes(), nil
}
