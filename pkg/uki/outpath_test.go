// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package uki

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("unsigned UKI output", func() {
	Describe("unsignedOutPath", func() {
		resolve := func(out string) string {
			return (&Builder{OutUKIPath: out}).unsignedOutPath()
		}

		It("renames the default signed name", func() {
			Expect(resolve("uki.signed.efi")).To(Equal("uki.unsigned.efi"))
			Expect(resolve("/srv/out/uki.signed.efi")).To(Equal("/srv/out/uki.unsigned.efi"))
		})

		It("leaves a name that already says unsigned alone", func() {
			// "unsigned" contains "signed", so a plain replace writes
			// "ununsigned" here and the caller never gets the file it named.
			Expect(resolve("/tmp/uki.unsigned.efi")).To(Equal("/tmp/uki.unsigned.efi"))
			Expect(resolve("unsigned.efi")).To(Equal("unsigned.efi"))
		})

		It("never rewrites a directory component", func() {
			Expect(resolve("/srv/signed-artifacts/uki.efi")).To(Equal("/srv/signed-artifacts/uki.efi"))
			Expect(resolve("/out/unsigned/uki.efi")).To(Equal("/out/unsigned/uki.efi"))
			Expect(resolve("/tmp/designed/uki.efi")).To(Equal("/tmp/designed/uki.efi"))
		})

		It("uses a name without signed in it verbatim", func() {
			Expect(resolve("/out/uki.efi")).To(Equal("/out/uki.efi"))
		})

		It("renames only the first occurrence in the name", func() {
			Expect(resolve("signed-signed.efi")).To(Equal("unsigned-signed.efi"))
		})
	})

	Describe("writeUnsignedUKI", func() {
		var builder *Builder
		var tmpDir string

		BeforeEach(func() {
			tmpDir = GinkgoT().TempDir()

			scratch := filepath.Join(tmpDir, "unsigned.uki")
			Expect(os.WriteFile(scratch, []byte("uki-payload"), 0o640)).To(Succeed())

			builder = &Builder{unsignedUKIPath: scratch}
		})

		It("writes into the directory the caller chose", func() {
			outDir := filepath.Join(tmpDir, "signed-artifacts")
			Expect(os.Mkdir(outDir, 0o750)).To(Succeed())
			builder.OutUKIPath = filepath.Join(outDir, "uki.efi")

			outPath, err := builder.writeUnsignedUKI()
			Expect(err).ToNot(HaveOccurred())
			Expect(outPath).To(Equal(builder.OutUKIPath))
			Expect(os.ReadFile(outPath)).To(Equal([]byte("uki-payload")))
		})

		It("carries the mode of the assembled file instead of 0777", func() {
			builder.OutUKIPath = filepath.Join(tmpDir, "uki.signed.efi")

			outPath, err := builder.writeUnsignedUKI()
			Expect(err).ToNot(HaveOccurred())
			Expect(outPath).To(Equal(filepath.Join(tmpDir, "uki.unsigned.efi")))

			info, err := os.Stat(outPath)
			Expect(err).ToNot(HaveOccurred())
			Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o640)))
		})

		It("reports the error when the assembled file is missing", func() {
			builder.unsignedUKIPath = filepath.Join(tmpDir, "absent.uki")
			builder.OutUKIPath = filepath.Join(tmpDir, "uki.signed.efi")

			_, err := builder.writeUnsignedUKI()
			Expect(err).To(HaveOccurred())
		})
	})
})
