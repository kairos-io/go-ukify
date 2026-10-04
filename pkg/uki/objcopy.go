// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package uki

import (
	"fmt"
	"os/exec"
)

const (
	// defaultObjcopy is the GNU objcopy, used for a single-profile UKI.
	defaultObjcopy = "objcopy"
	// defaultLLVMObjcopy is used when the UKI carries extra profiles, because
	// GNU objcopy refuses to add a section whose name the file already has and
	// a multi-profile UKI repeats .profile and .cmdline.
	defaultLLVMObjcopy = "llvm-objcopy"
)

// needsLLVMObjcopy reports whether this build has to go through llvm-objcopy.
func (builder *Builder) needsLLVMObjcopy() bool {
	return len(builder.ExtraCmdlines) > 0
}

// objcopyBinary returns the binary this build will run to assemble the UKI and
// the flag that overrides it. The binary is whatever the caller configured, or
// the default name, which exec resolves from $PATH.
func (builder *Builder) objcopyBinary() (binary, flag string) {
	if builder.needsLLVMObjcopy() {
		if builder.LLVMObjcopyPath != "" {
			return builder.LLVMObjcopyPath, "--llvm-objcopy"
		}

		return defaultLLVMObjcopy, "--llvm-objcopy"
	}

	if builder.ObjcopyPath != "" {
		return builder.ObjcopyPath, "--objcopy"
	}

	return defaultObjcopy, "--objcopy"
}

// resolveObjcopy locates the objcopy this build needs and returns its path.
//
// Build calls it before it generates a single section, because assemble is the
// last step: by the time exec would report a missing binary, the kernel and the
// initrd have been read and, with a PCR key, the policy has been signed for
// every bank and phase. The error names the binary and the flag that points at
// another one, which exec's own "executable file not found in $PATH" does not.
func (builder *Builder) resolveObjcopy() (string, error) {
	binary, flag := builder.objcopyBinary()

	path, err := exec.LookPath(binary)
	if err != nil {
		return "", fmt.Errorf("%q assembles the UKI and was not found: %w; install it, or set %s to one that can write a PE for the target architecture", binary, err, flag)
	}

	return path, nil
}
