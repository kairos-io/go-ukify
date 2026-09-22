// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package uki

import (
	"debug/pe"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/kairos-io/go-ukify/pkg/constants"
	"github.com/kairos-io/go-ukify/pkg/types"
)

func TestSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "UKI test Suite")
}

// The stub used as the base of the assembled image. It is a real PE32+ file
// with SectionAlignment 0x1000 and FileAlignment 0x200, like the systemd stub.
const testStub = "../pesign/testdata/file.efi"

var _ = Describe("assemble", func() {
	var builder *Builder
	var tmpDir string

	// writeSection writes size bytes to a file in the scratch dir and returns its path.
	writeSection := func(name string, size int) string {
		path := filepath.Join(tmpDir, name)
		Expect(os.WriteFile(path, make([]byte, size), 0o600)).To(Succeed())
		return path
	}

	BeforeEach(func() {
		if _, err := exec.LookPath("objcopy"); err != nil {
			Skip("objcopy is not installed")
		}

		var err error
		tmpDir, err = os.MkdirTemp("", "ukify-assemble")
		Expect(err).ToNot(HaveOccurred())

		builder = &Builder{
			SdStubPath: testStub,
			scratchDir: tmpDir,
		}
	})

	AfterEach(func() {
		Expect(os.RemoveAll(tmpDir)).To(Succeed())
	})

	It("starts every appended section on a SectionAlignment boundary", func() {
		// Sizes are deliberately not multiples of the alignment, and the kernel
		// comes last like in a real build, so the section before it ends inside
		// a page. The test stub already carries .osrel and .sbat, so those two
		// are not appended here; objcopy refuses a duplicate section name.
		builder.sections = []types.UkiSection{
			{Name: constants.CMDLine, Path: writeSection("cmdline", 177), Append: true},
			{Name: constants.Initrd, Path: writeSection("initrd", 3*4096+1000), Append: true},
			{Name: constants.SBAT, Path: writeSection("sbat", 100), Append: false},
			{Name: constants.Splash, Path: writeSection("splash", 4096+138), Append: true},
			{Name: constants.Uname, Path: writeSection("uname", 12), Append: true},
			{Name: constants.PCRPKey, Path: writeSection("pcrpkey", 451), Append: true},
			{Name: constants.Linux, Path: writeSection("linux", 2*4096+512), Append: true},
		}

		Expect(builder.assemble()).To(Succeed())

		stub, err := pe.Open(testStub)
		Expect(err).ToNot(HaveOccurred())
		defer stub.Close() //nolint: errcheck

		header, ok := stub.OptionalHeader.(*pe.OptionalHeader64)
		Expect(ok).To(BeTrue())
		alignment := uint64(header.SectionAlignment)
		Expect(alignment).To(Equal(uint64(0x1000)))

		out, err := pe.Open(builder.unsignedUKIPath)
		Expect(err).ToNot(HaveOccurred())
		defer out.Close() //nolint: errcheck

		byName := map[string]*pe.Section{}
		for _, s := range out.Sections {
			byName[s.Name] = s
		}

		var previousEnd uint64
		for _, section := range builder.sections {
			if !section.Append {
				continue
			}

			s, found := byName[string(section.Name)]
			Expect(found).To(BeTrue(), "section %s missing from the output", section.Name)

			// The computed address is what objcopy was told to use.
			Expect(section.VMA).To(Equal(header.ImageBase+uint64(s.VirtualAddress)),
				"section %s was placed at a different address than computed", section.Name)

			Expect(uint64(s.VirtualAddress)%alignment).To(BeZero(),
				"section %s starts at 0x%x, not on a 0x%x boundary", section.Name, s.VirtualAddress, alignment)

			Expect(uint64(s.VirtualAddress)).To(BeNumerically(">=", previousEnd),
				"section %s overlaps the section before it", section.Name)
			previousEnd = uint64(s.VirtualAddress) + uint64(s.VirtualSize)
		}

		// The appended sections come after everything the stub already had.
		lastStubSection := stub.Sections[len(stub.Sections)-1]
		first := byName[string(constants.CMDLine)]
		Expect(uint64(first.VirtualAddress)).To(BeNumerically(">=",
			uint64(lastStubSection.VirtualAddress)+uint64(lastStubSection.VirtualSize)))
	})
})

var _ = Describe("sectionAlignment", func() {
	It("uses the alignment from the header", func() {
		Expect(sectionAlignment(&pe.OptionalHeader64{SectionAlignment: 0x1000})).To(Equal(uint64(0x1000)))
		Expect(sectionAlignment(&pe.OptionalHeader64{SectionAlignment: 0x10000})).To(Equal(uint64(0x10000)))
	})

	It("falls back to the page size for a missing or broken value", func() {
		Expect(sectionAlignment(&pe.OptionalHeader64{SectionAlignment: 0})).To(Equal(uint64(0x1000)))
		Expect(sectionAlignment(&pe.OptionalHeader64{SectionAlignment: 0x1ff})).To(Equal(uint64(0x1000)))
	})
})

var _ = Describe("alignUp", func() {
	It("rounds up to the next multiple and leaves aligned values alone", func() {
		Expect(alignUp(0, 0x1000)).To(Equal(uint64(0)))
		Expect(alignUp(1, 0x1000)).To(Equal(uint64(0x1000)))
		Expect(alignUp(0x1000, 0x1000)).To(Equal(uint64(0x1000)))
		Expect(alignUp(0x1001, 0x1000)).To(Equal(uint64(0x2000)))
		Expect(alignUp(0x14dfad0b4, 0x1000)).To(Equal(uint64(0x14dfae000)))
	})
})
