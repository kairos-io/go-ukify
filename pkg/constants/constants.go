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
	// Systemd-measure uses the following phases:
	// "enter-initrd", "enter-initrd:leave-initrd", "enter-initrd:leave-initrd:sysinit", "enter-initrd:leave-initrd:sysinit:ready"
	EnterLeaveInitrd             Phase = "enter-initrd:leave-initrd"
	EnterLeaveInitrdSysinit      Phase = "enter-initrd:leave-initrd:sysinit"
	EnterLeaveInitrdSysinitReady Phase = "enter-initrd:leave-initrd:sysinit:ready"

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

// OrderedSections returns the sections that are measured into PCR.
//
// Derived from https://github.com/systemd/systemd/blob/main/src/fundamental/tpm-pcr.h#L23-L36
// .pcrsig section is omitted here since that's what we are calulating here.
func OrderedSections() []Section {
	// DO NOT REARRANGE
	return []Section{
		Linux,
		OSRel,
		CMDLine,
		Initrd,
		Splash,
		DTB,
		Uname,
		SBAT,
		PCRPKey}
}

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
