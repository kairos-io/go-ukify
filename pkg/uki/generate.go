// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package uki

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/kairos-io/go-ukify/internal/common"
	"github.com/kairos-io/go-ukify/pkg/types"
	"github.com/kairos-io/go-ukify/pkg/utils"

	"github.com/kairos-io/go-ukify/pkg/constants"
	"github.com/kairos-io/go-ukify/pkg/measure"
)

func (builder *Builder) generateOSRel() error {
	var path string
	if builder.OsRelease != "" {
		slog.Debug("Using existing os-release", "path", builder.OsRelease)
		path = builder.OsRelease
	} else {
		// Generate a simplified os-release
		slog.Debug("Generating a new os-release")
		osRelease, err := constants.OSReleaseFor(constants.Name, builder.Version)
		if err != nil {
			return err
		}
		path = filepath.Join(builder.scratchDir, "os-release")
		if err = os.WriteFile(path, osRelease, 0o600); err != nil {
			return err
		}
	}

	builder.sections = append(builder.sections,
		types.UkiSection{
			Name:    constants.OSRel,
			Path:    path,
			Measure: true,
			Append:  true,
		},
	)

	return nil
}

func (builder *Builder) generateCmdline() error {
	slog.Debug("Using cmdline", "cmdline", builder.Cmdline)
	path := filepath.Join(builder.scratchDir, "cmdline")

	if err := os.WriteFile(path, []byte(builder.Cmdline), 0o600); err != nil {
		return err
	}

	builder.sections = append(builder.sections,
		types.UkiSection{
			Name:    constants.CMDLine,
			Path:    path,
			Measure: true,
			Append:  true,
		},
	)
	builder.profileCmdlinePaths = append(builder.profileCmdlinePaths, path)

	return nil
}

func (builder *Builder) generateInitrd() error {
	slog.Debug("Using initrd", "path", builder.InitrdPath)
	builder.sections = append(builder.sections,
		types.UkiSection{
			Name:    constants.Initrd,
			Path:    builder.InitrdPath,
			Measure: true,
			Append:  true,
		},
	)

	return nil
}

func (builder *Builder) generateSplash() error {
	path := filepath.Join(builder.scratchDir, "splash.bmp")
	var data []byte

	if builder.Splash != "" {
		slog.Debug("Using splash", "file", builder.Splash)
		data, _ = os.ReadFile(builder.Splash)
	} else {
		slog.Debug("Using generic bundled splash")
		data = common.Logo
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}

	builder.sections = append(builder.sections,
		types.UkiSection{
			Name:    constants.Splash,
			Path:    path,
			Measure: true,
			Append:  true,
		},
	)

	return nil
}

func (builder *Builder) generateUname() error {
	// it is not always possible to get the kernel version from the kernel image, so we
	// do a bit of pre-checks
	var kernelVersion string

	// otherwise, try to get the kernel version from the kernel image
	kernelVersion, _ = DiscoverKernelVersion(builder.KernelPath) //nolint:errcheck

	if kernelVersion == "" {
		// we haven't got the kernel version, skip the uname section
		slog.Info("We could not infer kernel version", "path", builder.KernelPath)
		return nil
	} else {
		slog.Debug("Getting uname", "version", kernelVersion, "path", builder.KernelPath)
	}

	path := filepath.Join(builder.scratchDir, "uname")

	if err := os.WriteFile(path, []byte(kernelVersion), 0o600); err != nil {
		return err
	}

	builder.sections = append(builder.sections,
		types.UkiSection{
			Name:    constants.Uname,
			Path:    path,
			Measure: true,
			Append:  true,
		},
	)

	return nil
}

func (builder *Builder) generateSBAT() error {
	slog.Debug("Getting SBAT", "path", builder.SdStubPath)
	sbat, err := GetSBAT(builder.SdStubPath)
	if err != nil {
		return err
	}

	slog.Debug("Generated SBAT", "sbat", sbat, "path", builder.SdStubPath)

	path := filepath.Join(builder.scratchDir, "sbat")

	if err = os.WriteFile(path, sbat, 0o600); err != nil {
		return err
	}

	// SBAT needs to be measured but NOT added
	// This is because we build with the systemd-stub as base, and that already has a .sbat section!
	// So int he final PE file we will get the .sbat section in there, so we need to measure.
	builder.sections = append(builder.sections,
		types.UkiSection{
			Name:    constants.SBAT,
			Path:    path,
			Measure: true,
		},
	)

	return nil
}

func (builder *Builder) generatePCRPublicKey() error {
	if !builder.pcrSignEnabled() {
		return nil
	}
	slog.Debug("Getting Public PCR key")
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(builder.PCRSigner.PublicRSAKey())
	if err != nil {
		return err
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  constants.PEMTypeRSAPublic,
		Bytes: publicKeyBytes,
	})

	path := filepath.Join(builder.scratchDir, "pcr-public.pem")

	if err = os.WriteFile(path, publicKeyPEM, 0o600); err != nil {
		return err
	}

	builder.sections = append(builder.sections,
		types.UkiSection{
			Name:    constants.PCRPKey,
			Path:    path,
			Append:  true,
			Measure: true,
		},
	)

	return nil

}

func (builder *Builder) generateKernel() error {
	slog.Debug("Getting kernel")

	builder.sections = append(builder.sections,
		types.UkiSection{
			Name:    constants.Linux,
			Path:    builder.KernelPath,
			Append:  true,
			Measure: true,
		},
	)

	return nil
}

func (builder *Builder) generatePCRSig() error {
	if len(builder.ExtraCmdlines) > 0 {
		return nil // handled per-profile above
	}
	slog.Info("Generating PCR measurements")
	slog.Debug("Using PCR slot", "number", constants.UKIPCR)
	sectionsData := utils.SectionsData(builder.sections)

	// If we have the signer sign the measurements and attach them to the uki file
	if builder.pcrSignEnabled() {
		slog.Info("Generating signed policy per profile")
		// ensure we have at least the base cmdline recorded
		if len(builder.profileCmdlinePaths) == 0 {
			slog.Debug("profileCmdlinePaths empty; falling back to current sectionsData .cmdline")
			builder.profileCmdlinePaths = append(builder.profileCmdlinePaths, sectionsData[constants.CMDLine])
		}
		for i, cmd := range builder.profileCmdlinePaths {
			// clone & override the cmdline for this profile
			override := map[constants.Section]string{}
			for k, v := range sectionsData {
				override[k] = v
			}
			override[constants.CMDLine] = cmd

			pcrData, err := measure.GenerateSignedPCR(override, builder.Phases, builder.PCRSigner, constants.UKIPCR)
			if err != nil {
				return err
			}
			pcrSignatureData, err := json.Marshal(pcrData)
			if err != nil {
				return err
			}
			path := filepath.Join(builder.scratchDir, fmt.Sprintf("pcrpsig-%d", i))
			if err = os.WriteFile(path, pcrSignatureData, 0o600); err != nil {
				return err
			}
			builder.sections = append(builder.sections,
				types.UkiSection{
					Name:   constants.PCRSig,
					Path:   path,
					Append: true,
				},
			)
		}
	} else {
		// For visibility, print measurements for the base and extras
		if len(builder.profileCmdlinePaths) == 0 {
			measure.GenerateMeasurements(sectionsData, builder.Phases, constants.UKIPCR)
		} else {
			for _, cmd := range builder.profileCmdlinePaths {
				override := map[constants.Section]string{}
				for k, v := range sectionsData {
					override[k] = v
				}
				override[constants.CMDLine] = cmd
				measure.GenerateMeasurements(override, builder.Phases, constants.UKIPCR)
			}
		}
	}

	return nil
}

// generateBaseProfileAndSig emits a minimal base .profile and a .pcrsig
// signed over the shared sections + BASE cmdline when extra profiles are used.
// If there are no ExtraCmdlines, it does nothing (single-profile flow).
func (builder *Builder) generateBaseProfileAndSig() error {
	if len(builder.ExtraCmdlines) == 0 {
		// single-profile: handled later by generatePCRSig()
		return nil
	}

	// 1) .profile (base)
	profPath := filepath.Join(builder.scratchDir, "profile-base")
	// Minimal body so bootctl shows something nice
	body := []byte("ID=base\nTITLE=Default profile\n")
	if err := os.WriteFile(profPath, body, 0o600); err != nil {
		return err
	}
	builder.sections = append(builder.sections, types.UkiSection{
		Name:   constants.Profile,
		Path:   profPath,
		Append: true,
		// not measured
	})

	// 2) .pcrsig (base) — sign over current sections with BASE cmdline
	if !builder.pcrSignEnabled() {
		// no signing: measurements will be printed later
		return nil
	}

	// Build map of measured sections and force base cmdline
	sectionsData := utils.SectionsData(builder.sections)
	baseCmd := sectionsData[constants.CMDLine]
	if len(builder.profileCmdlinePaths) > 0 && builder.profileCmdlinePaths[0] != "" {
		baseCmd = builder.profileCmdlinePaths[0]
	}
	override := map[constants.Section]string{}
	for k, v := range sectionsData {
		override[k] = v
	}
	override[constants.CMDLine] = baseCmd

	slog.Info("Generating signed PCR policy (base profile)")
	pcrData, err := measure.GenerateSignedPCR(override, builder.Phases, builder.PCRSigner, constants.UKIPCR)
	if err != nil {
		return err
	}
	pcrJSON, err := json.Marshal(pcrData)
	if err != nil {
		return err
	}
	sigPath := filepath.Join(builder.scratchDir, "pcrpsig-base")
	if err := os.WriteFile(sigPath, pcrJSON, 0o600); err != nil {
		return err
	}
	builder.sections = append(builder.sections, types.UkiSection{
		Name:   constants.PCRSig,
		Path:   sigPath,
		Append: true,
	})
	return nil
}

func (builder *Builder) generateExtraProfiles() error {
	if len(builder.ExtraCmdlines) == 0 {
		return nil
	}

	for i, line := range builder.ExtraCmdlines {
		// 1) .profile (extra i+1)
		profPath := filepath.Join(builder.scratchDir, fmt.Sprintf("profile-%d", i+1))
		// Keep TITLE simple; adjust if you later add a separate --extra-title
		profBody := []byte(fmt.Sprintf("ID=extra-%d\nTITLE=extra-%d\n", i+1, i+1))
		if err := os.WriteFile(profPath, profBody, 0o600); err != nil {
			return err
		}
		builder.sections = append(builder.sections, types.UkiSection{
			Name:   constants.Profile,
			Path:   profPath,
			Append: true,
		})

		// 2) .cmdline for this profile
		cmdPath := filepath.Join(builder.scratchDir, fmt.Sprintf("cmdline-extra-%d", i+1))
		if err := os.WriteFile(cmdPath, []byte(line), 0o600); err != nil {
			return err
		}
		builder.sections = append(builder.sections, types.UkiSection{
			Name:    constants.CMDLine,
			Path:    cmdPath,
			Measure: true,
			Append:  true,
		})
		builder.profileCmdlinePaths = append(builder.profileCmdlinePaths, cmdPath)

		// 3) .pcrsig for this profile
		if builder.pcrSignEnabled() {
			sectionsData := utils.SectionsData(builder.sections)
			override := map[constants.Section]string{}
			for k, v := range sectionsData {
				override[k] = v
			}
			override[constants.CMDLine] = cmdPath

			slog.Info("Generating signed PCR policy", "profile", i+1)
			pcrData, err := measure.GenerateSignedPCR(override, builder.Phases, builder.PCRSigner, constants.UKIPCR)
			if err != nil {
				return err
			}
			pcrJSON, err := json.Marshal(pcrData)
			if err != nil {
				return err
			}
			sigPath := filepath.Join(builder.scratchDir, fmt.Sprintf("pcrpsig-%d", i+1))
			if err := os.WriteFile(sigPath, pcrJSON, 0o600); err != nil {
				return err
			}
			builder.sections = append(builder.sections, types.UkiSection{
				Name:   constants.PCRSig,
				Path:   sigPath,
				Append: true,
			})
		}
	}
	return nil
}
