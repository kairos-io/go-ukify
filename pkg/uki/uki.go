// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package uki creates the UKI file out of the sd-stub and other sections.
package uki

import (
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/kairos-io/go-ukify/pkg/pesign"
	"github.com/kairos-io/go-ukify/pkg/types"
)

// Builder is a UKI file builder.
type Builder struct {
	// Source options.
	//
	// Arch of the UKI file.
	Arch string
	// Version of Talos.
	Version string
	// Path to the sd-stub.
	SdStubPath string
	// Path to the sd-boot.
	SdBootPath string
	// Path to the kernel image.
	KernelPath string
	// Path to the initrd image.
	InitrdPath string
	// Kernel cmdline.
	Cmdline string
	// Os-release file
	OsRelease string
	// Phases to measure for
	Phases []types.PhaseInfo

	// SecureBoot certificate and signer.
	SecureBootSigner *pesign.Signer
	// SecureBoot key
	SBKey string
	// SecureBoot cert
	SBCert string

	// PCR signer.
	PCRSigner types.RSAKey
	// Path to the PCR signing key
	PCRKey string

	Splash string

	// Output options:
	//
	// Path to the signed sd-boot.
	OutSdBootPath string
	// Path to the output UKI file.
	OutUKIPath string

	// fields initialized during build
	sections        []types.UkiSection
	scratchDir      string
	unsignedUKIPath string

	ExtraCmdlines       []string
	profileCmdlinePaths []string
}

// Build the UKI file.
//
// Build process is as follows:
//   - sign the sd-boot EFI binary, and write it to the OutSdBootPath
//   - build ephemeral sections (uname, os-release), and other proposed sections
//   - measure sections, generate signature, and append to the list of sections
//   - assemble the final UKI file starting from sd-stub and appending generated section.
func (builder *Builder) Build() error {
	var err error

	// Check if we got any phases
	if len(builder.Phases) == 0 {
		// use default phases
		builder.Phases = types.OrderedPhases()
	}

	if builder.PCRSigner == nil {
		if builder.PCRKey != "" {
			signer, err := pesign.NewPCRSigner(builder.PCRKey)
			if err != nil {
				return err
			}
			builder.PCRSigner = signer
		}
	}

	// Try to generate a signer base on our given args
	// If we have a	either a signer or key/cert
	// Try to use first the signer as we can use a custom signed passed in the struct
	// otherwise create a new default signer with the key and cert
	if builder.sbSignEnabled() {
		if builder.SecureBootSigner == nil {
			if builder.SBCert != "" && builder.SBKey != "" {
				sb, err := pesign.NewSecureBootSigner(builder.SBCert, builder.SBKey)
				if err != nil {
					return err
				}
				sbSigner, err := pesign.NewSigner(sb)
				if err != nil {
					return err
				}
				builder.SecureBootSigner = sbSigner
			}
		}
	}

	builder.scratchDir, err = os.MkdirTemp("", "ukify")
	if err != nil {
		return err
	}

	defer func() {
		if err = os.RemoveAll(builder.scratchDir); err != nil {
			log.Printf("failed to remove scratch dir: %v", err)
		}
	}()

	// Sign sd-boot if given and signing is enabled
	if builder.SdBootPath != "" && builder.sbSignEnabled() {
		slog.Info("Signing systemd-boot", "path", builder.SdBootPath)

		// sign sd-boot
		if err = builder.SecureBootSigner.Sign(builder.SdBootPath, builder.OutSdBootPath); err != nil {
			return fmt.Errorf("error signing sd-boot: %w", err)
		}

		slog.Info("Signed systemd-boot", "path", builder.OutSdBootPath)
	} else {
		slog.Info("Not signing systemd-boot")
	}

	slog.Info("Generating UKI sections")

	// generate and build list of all sections
	for _, generateSection := range []func() error{
		builder.generateOSRel,
		builder.generateCmdline,
		builder.generateInitrd,
		builder.generateSplash,
		builder.generateUname,
		builder.generateSBAT,
		builder.generatePCRPublicKey,
		// append kernel last to account for decompression
		builder.generateKernel,            // shared payload ends here
		builder.generateBaseProfileAndSig, // emits .profile(base) + .pcrsig(base) if extras exist
		builder.generateExtraProfiles,     // emits (.profile + .cmdline + .pcrsig) per extra
		// measure sections last
		builder.generatePCRSig,
	} {
		if err = generateSection(); err != nil {
			return fmt.Errorf("error generating sections: %w", err)
		}
	}

	slog.Info("Generated UKI sections")

	slog.Info("Assembling UKI")

	// assemble the final UKI file
	if err = builder.assemble(); err != nil {
		return fmt.Errorf("error assembling UKI: %w", err)
	}

	slog.Info("Assembled UKI")

	// sign the UKI file if signing is enabled
	if builder.sbSignEnabled() {
		slog.Info("Signing UKI")
		err = builder.SecureBootSigner.Sign(builder.unsignedUKIPath, builder.OutUKIPath)
		if err == nil {
			slog.Info(fmt.Sprintf("Signed UKI at %s", builder.OutUKIPath))
		}
	} else {
		// Move it to final place as we will remove the scratch dir
		outPath, err := builder.writeUnsignedUKI()
		if err != nil {
			return err
		}
		slog.Info(fmt.Sprintf("Unsigned UKI at %s", outPath))
	}

	return err
}

// writeUnsignedUKI copies the assembled UKI out of the scratch directory, which
// Build removes on the way out, and returns the path it was written to.
//
// The mode is taken from the assembled file, so an unsigned build produces the
// same permissions as a signed one, which pesign.Sign also carries over from
// its input.
func (builder *Builder) writeUnsignedUKI() (string, error) {
	info, err := os.Stat(builder.unsignedUKIPath)
	if err != nil {
		return "", err
	}

	body, err := os.ReadFile(builder.unsignedUKIPath)
	if err != nil {
		return "", err
	}

	outPath := builder.unsignedOutPath()
	// The output path is the one the caller passed in --output, which is the
	// whole point of the flag, so gosec G703 (path traversal from os.Args) has
	// nothing to confine it to. The signed branch writes the same caller path
	// through pesign.Sign.
	// #nosec G703
	if err := os.WriteFile(outPath, body, info.Mode()); err != nil {
		return "", err
	}

	return outPath, nil
}

// unsignedOutPath is where an unsigned UKI is written.
//
// The artifact is not signed, so a name that says "signed" would be wrong, and
// the default output name is uki.signed.efi. Renaming is therefore done on the
// file name alone: the directory the caller chose is never rewritten, and a
// name that already says "unsigned" is left as it is rather than turned into
// "ununsigned", because "unsigned" contains "signed". A name with no "signed"
// in it is used verbatim.
//
// OutUKIPath is the only output contract the caller has, so anything this
// function cannot rename safely it must leave alone.
func (builder *Builder) unsignedOutPath() string {
	dir, name := filepath.Split(builder.OutUKIPath)

	if !strings.Contains(name, "unsigned") {
		name = strings.Replace(name, "signed", "unsigned", 1)
	}

	return filepath.Join(dir, name)
}

// sbSignEnabled let us know if we have to sign the sd-boot and uki final file
// Checks if we have a signer or a key/cert pair to sign
func (builder *Builder) sbSignEnabled() bool {
	return builder.SecureBootSigner != nil || (builder.SBKey != "" && builder.SBCert != "")
}

// pcrSignEnabled let us know if we have to sign the measurements
// Checks if we have a pcr signer or a pcrkey
func (builder *Builder) pcrSignEnabled() bool {
	return builder.PCRSigner != nil || builder.PCRKey != ""
}
