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
		builder.generateKernel,
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
		fileRead, err := os.ReadFile(builder.unsignedUKIPath)
		if err != nil {
			return err
		}
		err = os.WriteFile(strings.Replace(builder.OutUKIPath, "signed", "unsigned", -1), fileRead, os.ModePerm)
		if err != nil {
			return err
		}
		slog.Info(fmt.Sprintf("Unsigned UKI at %s", strings.Replace(builder.OutUKIPath, "signed", "unsigned", -1)))
	}

	return err
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
