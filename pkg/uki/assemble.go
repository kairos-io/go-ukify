// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package uki

import (
	"debug/pe"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
)

// assemble the UKI file out of sections.
func (builder *Builder) assemble() error {

	// Prefer llvm-objcopy when we have repeated section names (.profile/.cmdline)
	useLLVM := len(builder.ExtraCmdlines) > 0
	objcopy := "objcopy"
	if useLLVM {
		objcopy = "llvm-objcopy"
	}

	peFile, err := pe.Open(builder.SdStubPath)
	if err != nil {
		return err
	}

	defer peFile.Close() //nolint: errcheck

	// find the first VMA address
	lastSection := peFile.Sections[len(peFile.Sections)-1]

	header, ok := peFile.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		return errors.New("failed to get optional header")
	}

	// Every section we append must start at a multiple of the SectionAlignment
	// the stub's PE header declares (0x1000 for the systemd stub). That is what
	// the PE format requires and what systemd's ukify does. Firmware that applies
	// per-section memory protection (edk2 DxeCore with an image protection
	// policy, which OVMF enables in its SecureBoot build) sets page attributes on
	// each code section and on the data between them. A section that starts
	// inside a page makes those ranges impossible to express, the firmware
	// refuses them, and in a DEBUG firmware build the refusal is an ASSERT that
	// spins forever until the boot-services watchdog resets the machine.
	// Aligning to 512 bytes, as this code did before, produced exactly that PE.
	alignment := sectionAlignment(header)

	baseVMA := alignUp(header.ImageBase+uint64(lastSection.VirtualAddress)+uint64(lastSection.VirtualSize), alignment)

	// calculate sections size and VMA
	for i := range builder.sections {
		if !builder.sections[i].Append {
			continue
		}

		st, err := os.Stat(builder.sections[i].Path)
		if err != nil {
			return err
		}

		builder.sections[i].Size = uint64(st.Size())
		builder.sections[i].VMA = baseVMA

		baseVMA = alignUp(baseVMA+builder.sections[i].Size, alignment)
	}

	// create the output file
	args := []string{}

	for _, section := range builder.sections {
		if !section.Append {
			continue
		}

		args = append(args, "--add-section", fmt.Sprintf("%s=%s", section.Name, section.Path))
		// llvm-objcopy does not support --change-section-vma; skip it and rely on order
		if !useLLVM {
			args = append(args, "--change-section-vma", fmt.Sprintf("%s=0x%x", section.Name, section.VMA))
		}
	}

	// Set the section flag to CODE for .linux not usre if this does anything?
	args = append(args, "--set-section-flags", ".linux=code,readonly")

	// mark all payload sections as readable (llvm-objcopy default lacks MEM_READ)
	for _, sec := range []string{
		".osrel", ".cmdline", ".initrd", ".splash", ".uname",
		".pcrpkey", ".pcrsig", ".profile",
	} {
		args = append(args, "--set-section-flags", fmt.Sprintf("%s=data,readonly", sec))
	}

	builder.unsignedUKIPath = filepath.Join(builder.scratchDir, "unsigned.uki")

	args = append(args, builder.SdStubPath, builder.unsignedUKIPath)

	slog.Debug("Assembling", "args", args)

	cmd := exec.Command(objcopy, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// defaultSectionAlignment is the page size every UEFI target uses and the value
// the systemd stub is linked with. It is the fallback for a header that does not
// declare a usable SectionAlignment.
const defaultSectionAlignment = 0x1000

// sectionAlignment returns the alignment every section of the image must start
// at, taken from the PE optional header. A missing value or one that is not a
// power of two falls back to the page size, which is the strictest alignment a
// UEFI loader asks for.
func sectionAlignment(header *pe.OptionalHeader64) uint64 {
	alignment := uint64(header.SectionAlignment)
	if alignment == 0 || alignment&(alignment-1) != 0 {
		return defaultSectionAlignment
	}

	return alignment
}

// alignUp rounds value up to the next multiple of alignment, which must be a
// power of two.
func alignUp(value, alignment uint64) uint64 {
	return (value + alignment - 1) &^ (alignment - 1)
}
