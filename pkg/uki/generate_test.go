package uki

import (
	"os"
	"path/filepath"

	"github.com/kairos-io/go-ukify/pkg/constants"
	"github.com/kairos-io/go-ukify/pkg/types"
	"github.com/kairos-io/go-ukify/pkg/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

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

var _ = Describe("Splash section", func() {
	var builder *Builder

	BeforeEach(func() {
		dir, err := os.MkdirTemp("", "ukify-splash")
		Expect(err).ToNot(HaveOccurred())
		DeferCleanup(func() { Expect(os.RemoveAll(dir)).To(Succeed()) })

		builder = &Builder{scratchDir: dir}
	})

	// The .splash section is signed and measured into PCR 11, so a splash we
	// cannot read has to stop the build. Writing an empty section instead hands
	// the operator a signed UKI with their branding silently missing.
	It("fails when the named splash cannot be read", func() {
		builder.Splash = filepath.Join(builder.scratchDir, "does-not-exist.bmp")

		err := builder.generateSplash()
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("does-not-exist.bmp"))
		Expect(builder.sections).To(BeEmpty(), "no section may be added for a splash we could not read")
	})

	It("embeds the splash the operator named", func() {
		builder.Splash = filepath.Join(builder.scratchDir, "logo.bmp")
		Expect(os.WriteFile(builder.Splash, []byte("BMsplash"), 0o600)).To(Succeed())

		Expect(builder.generateSplash()).To(Succeed())
		Expect(utils.SectionsData(builder.sections)).To(HaveKey(constants.Splash))
		Expect(os.ReadFile(utils.SectionsData(builder.sections)[constants.Splash])).
			To(Equal([]byte("BMsplash")))
	})

	It("falls back to the bundled splash when none is named", func() {
		Expect(builder.generateSplash()).To(Succeed())
		data, err := os.ReadFile(utils.SectionsData(builder.sections)[constants.Splash])
		Expect(err).ToNot(HaveOccurred())
		Expect(data).ToNot(BeEmpty())
	})
})
