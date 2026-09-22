package constants_test

import (
	"testing"

	"github.com/kairos-io/go-ukify/pkg/constants"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Constants test Suite")
}

var _ = Describe("OrderedSections", func() {
	// systemd-stub measures every unified section except .pcrsig, in the order
	// of its own UnifiedSection enum. See unified_section_measure() and
	// unified_sections in src/fundamental/uki.h and uki.c.
	It("lists the sections systemd-stub measures, in the order it measures them", func() {
		Expect(constants.OrderedSections()).To(Equal([]constants.Section{
			constants.Linux,
			constants.OSRel,
			constants.CMDLine,
			constants.Initrd,
			constants.Splash,
			constants.DTB,
			constants.Uname,
			constants.SBAT,
			constants.PCRPKey,
			constants.Profile,
		}))
	})
})
