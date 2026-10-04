// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package uki

import (
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/kairos-io/go-ukify/pkg/constants"
	"github.com/kairos-io/go-ukify/pkg/types"
)

var _ = Describe("objcopy selection", func() {
	var builder *Builder
	var tmpDir string

	// fakeObjcopy writes an executable that records its arguments and exits 0.
	fakeObjcopy := func(name string) (binary, log string) {
		binary = filepath.Join(tmpDir, name)
		log = filepath.Join(tmpDir, name+".args")
		script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + log + "\n"
		// #nosec G306 -- the helper has to be executable; it is written into the spec's own temp dir and deleted in AfterEach
		Expect(os.WriteFile(binary, []byte(script), 0o700)).To(Succeed())
		return binary, log
	}

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "ukify-objcopy")
		Expect(err).ToNot(HaveOccurred())

		builder = &Builder{SdStubPath: testStub, scratchDir: tmpDir}
	})

	AfterEach(func() {
		Expect(os.RemoveAll(tmpDir)).To(Succeed())
	})

	Describe("objcopyBinary", func() {
		It("defaults to objcopy for a single-profile UKI", func() {
			binary, flag := builder.objcopyBinary()
			Expect(binary).To(Equal("objcopy"))
			Expect(flag).To(Equal("--objcopy"))
		})

		It("defaults to llvm-objcopy once the UKI carries extra profiles", func() {
			builder.ExtraCmdlines = []string{"rd.break"}

			binary, flag := builder.objcopyBinary()
			Expect(binary).To(Equal("llvm-objcopy"))
			Expect(flag).To(Equal("--llvm-objcopy"))
		})

		It("takes the configured path instead of the default name", func() {
			builder.ObjcopyPath = "/opt/cross/bin/aarch64-linux-gnu-objcopy"

			binary, _ := builder.objcopyBinary()
			Expect(binary).To(Equal("/opt/cross/bin/aarch64-linux-gnu-objcopy"))
		})

		It("takes the configured llvm path for a multi-profile UKI", func() {
			builder.ExtraCmdlines = []string{"rd.break"}
			builder.ObjcopyPath = "/opt/cross/bin/aarch64-linux-gnu-objcopy"
			builder.LLVMObjcopyPath = "/usr/lib/llvm-18/bin/llvm-objcopy"

			binary, _ := builder.objcopyBinary()
			Expect(binary).To(Equal("/usr/lib/llvm-18/bin/llvm-objcopy"))
		})
	})

	Describe("resolveObjcopy", func() {
		It("returns the path of a binary that exists", func() {
			binary, _ := fakeObjcopy("objcopy-present")
			builder.ObjcopyPath = binary

			Expect(builder.resolveObjcopy()).To(Equal(binary))
		})

		It("names the missing binary and the flag that replaces it", func() {
			builder.ObjcopyPath = filepath.Join(tmpDir, "no-such-objcopy")

			_, err := builder.resolveObjcopy()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("no-such-objcopy"))
			Expect(err.Error()).To(ContainSubstring("--objcopy"))
		})

		It("names the llvm flag when the multi-profile tool is the missing one", func() {
			builder.ExtraCmdlines = []string{"rd.break"}
			builder.LLVMObjcopyPath = filepath.Join(tmpDir, "no-such-llvm-objcopy")

			_, err := builder.resolveObjcopy()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("no-such-llvm-objcopy"))
			Expect(err.Error()).To(ContainSubstring("--llvm-objcopy"))
		})
	})

	Describe("assemble", func() {
		It("runs the configured binary rather than the one on PATH", func() {
			binary, log := fakeObjcopy("recording-objcopy")
			builder.ObjcopyPath = binary
			builder.sections = []types.UkiSection{
				{Name: constants.CMDLine, Path: filepath.Join(tmpDir, "cmdline"), Append: true},
			}
			Expect(os.WriteFile(builder.sections[0].Path, []byte("quiet"), 0o600)).To(Succeed())

			Expect(builder.assemble()).To(Succeed())

			args, err := os.ReadFile(log)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(args)).To(ContainSubstring("--add-section"))
			Expect(strings.TrimSpace(string(args))).To(HaveSuffix(builder.unsignedUKIPath))
		})

		It("fails with the override hint when the binary is missing", func() {
			builder.ObjcopyPath = filepath.Join(tmpDir, "absent-objcopy")
			builder.sections = nil

			err := builder.assemble()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("--objcopy"))
		})
	})

	Describe("Build", func() {
		// SdStubPath is deliberately absent: generateSBAT reads it while
		// generating sections, which is after the objcopy check and before
		// assemble. Getting the objcopy error back rather than a stub read
		// error is what proves the check runs first.
		It("refuses a missing objcopy before it generates a single section", func() {
			builder.SdStubPath = filepath.Join(tmpDir, "no-such-stub.efi")
			builder.ObjcopyPath = filepath.Join(tmpDir, "absent-objcopy")
			builder.KernelPath = filepath.Join(tmpDir, "vmlinuz")
			builder.InitrdPath = filepath.Join(tmpDir, "initrd")
			builder.OutUKIPath = filepath.Join(tmpDir, "uki.signed.efi")
			Expect(os.WriteFile(builder.KernelPath, []byte("kernel"), 0o600)).To(Succeed())
			Expect(os.WriteFile(builder.InitrdPath, []byte("initrd"), 0o600)).To(Succeed())

			err := builder.Build()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("absent-objcopy"))
			Expect(err.Error()).To(ContainSubstring("--objcopy"))
		})
	})
})
