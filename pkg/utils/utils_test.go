package utils

import (
	"github.com/kairos-io/go-ukify/pkg/constants"
	"github.com/kairos-io/go-ukify/pkg/types"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Utils test Suite")
}

var _ = Describe("Utils tests", func() {
	Describe("SectionsDataV2", func() {
		var ukiSections []types.UkiSection
		var cmdlineSection types.UkiSection
		var unameSection types.UkiSection
		var notMeasuredSection types.UkiSection
		var expectedSections map[constants.Section]string
		var tmpDir string
		var err error

		BeforeEach(func() {
			tmpDir, err = os.MkdirTemp("", "")
			Expect(err).ToNot(HaveOccurred())

			err = os.WriteFile(filepath.Join(tmpDir, "cmdline"), []byte("root=LABEL=BOOT"), 777)
			Expect(err).ToNot(HaveOccurred())

			err = os.WriteFile(filepath.Join(tmpDir, "uname"), []byte("6.5.0"), 777)
			Expect(err).ToNot(HaveOccurred())

			cmdlineSection = types.UkiSection{
				Name:    constants.CMDLine,
				Path:    filepath.Join(tmpDir, "cmdline"),
				Measure: true,
			}

			unameSection = types.UkiSection{
				Name:    constants.Uname,
				Path:    filepath.Join(tmpDir, "uname"),
				Measure: true,
			}

			// This section should not appear in the final list from SectionsData as its not measured
			notMeasuredSection = types.UkiSection{
				Name:    constants.PCRSig,
				Path:    "/dev/null",
				Measure: false,
			}

			ukiSections = []types.UkiSection{
				cmdlineSection,
				unameSection,
				notMeasuredSection,
			}

			// This is what we expect from the SectionsData output
			expectedSections = map[constants.Section]string{
				constants.Uname:   filepath.Join(tmpDir, "uname"),
				constants.CMDLine: filepath.Join(tmpDir, "cmdline"),
			}
		})
		AfterEach(func() {
			Expect(os.RemoveAll(tmpDir)).ToNot(HaveOccurred())
		})
		It("Returns the expected sections", func() {
			Expect(SectionsData(ukiSections)).To(Equal(expectedSections))
		})
	})
})
