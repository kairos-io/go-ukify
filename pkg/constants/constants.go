package constants

import (
	"bytes"
	"strings"
	"text/template"
)

// Section is a name of a PE file section (UEFI binary).
type Section string

// Phase is the phase value extended to the PCR.
type Phase string

const (
	PEMTypeRSAPublic = "PUBLIC KEY"
	Name             = "Kairos"
	// UKIPCR is the PCR number where sections except `.pcrsig` are measured.
	UKIPCR            = 11
	OSReleaseTemplate = `NAME="{{ .Name }}"
ID={{ .ID }}
VERSION_ID={{ .Version }}
PRETTY_NAME="{{ .Name }} ({{ .Version }})"
)
`
	// EnterInitrd is the phase value extended to the PCR during the initrd.
	EnterInitrd Phase = "enter-initrd"
	// LeaveInitrd is the phase value extended to the PCR just before switching to machined.
	LeaveInitrd Phase = "leave-initrd"
	// EnterMachined is the phase value extended to the PCR before starting machined.
	// There should be only a signed signature for the enter-machined phase.
	EnterMachined Phase = "enter-machined"

	// List of well-known section names.
	Linux   Section = ".linux"
	OSRel   Section = ".osrel"
	CMDLine Section = ".cmdline"
	Initrd  Section = ".initrd"
	Splash  Section = ".splash"
	DTB     Section = ".dtb"
	Uname   Section = ".uname"
	SBAT    Section = ".sbat"
	PCRSig  Section = ".pcrsig"
	PCRPKey Section = ".pcrpkey"
)

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
