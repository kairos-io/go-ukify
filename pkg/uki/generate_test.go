package uki

import (
	"os"
	"testing"

	"github.com/kairos-io/go-ukify/pkg/constants"
	"github.com/kairos-io/go-ukify/pkg/types"
	"github.com/kairos-io/go-ukify/pkg/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "UKI test Suite")
}

var _ = Describe("Multi-profile sections", func() {
	var builder *Builder

	BeforeEach(func() {
		dir, err := os.MkdirTemp("", "ukify-generate")
		Expect(err).ToNot(HaveOccurred())
		DeferCleanup(func() { Expect(os.RemoveAll(dir)).To(Succeed()) })

		builder = &Builder{
			scratchDir:    dir,
			Cmdline:       "root=LABEL=COS_ACTIVE",
			ExtraCmdlines: []string{"root=LABEL=COS_ACTIVE rd.immucore.debug"},
		}

		Expect(builder.generateCmdline()).To(Succeed())
		Expect(builder.generateBaseProfileAndSig()).To(Succeed())
		Expect(builder.generateExtraProfiles()).To(Succeed())
	})

	// systemd-stub measures the .profile section of the selected profile into
	// PCR 11 along with the rest of the sections. A .profile we do not measure
	// is a PCR 11 value the signed policy can never match.
	It("marks every .profile section as measured", func() {
		var profiles int
		for _, s := range builder.sections {
			if s.Name == constants.Profile {
				profiles++
				Expect(s.Measure).To(BeTrue(), "section %s at %s is not measured", s.Name, s.Path)
			}
		}
		Expect(profiles).To(Equal(2), "expected a base profile and one extra profile")
	})

	// SectionsData keeps the last entry for a repeated name, so the map handed
	// to the signer carries the profile the .pcrsig is being generated for.
	It("hands the current profile to the measurement", func() {
		Expect(utils.SectionsData(builder.sections)).To(HaveKeyWithValue(
			constants.Profile, lastProfilePath(builder.sections)))
	})
})

// lastProfilePath returns the path of the last .profile section, which is the
// profile the .pcrsig being generated belongs to.
func lastProfilePath(sections []types.UkiSection) string {
	var path string
	for _, s := range sections {
		if s.Name == constants.Profile {
			path = s.Path
		}
	}
	return path
}
