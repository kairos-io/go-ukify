package constants_test

import (
	"strings"
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

var _ = Describe("OSReleaseFor", func() {
	// os-release is specified as a shell-compatible fragment of KEY=VALUE
	// assignments, and sourcing it is the documented way to read it. One line
	// that is not an assignment makes the whole file unreadable that way, which
	// is what a stray ")" left in the template used to do.
	It("emits only key/value lines", func() {
		content, err := constants.OSReleaseFor(constants.Name, "v3.5.0")
		Expect(err).ToNot(HaveOccurred())

		for _, line := range strings.Split(string(content), "\n") {
			if line == "" {
				continue
			}
			key, _, found := strings.Cut(line, "=")
			Expect(found).To(BeTrue(), "line %q is not a key/value pair", line)
			Expect(key).ToNot(BeEmpty(), "line %q has no key", line)
			Expect(key).To(MatchRegexp(`^[A-Z][A-Z0-9_]*$`),
				"line %q does not start with an os-release key", line)
		}
	})

	It("names the release it was given", func() {
		content, err := constants.OSReleaseFor(constants.Name, "v3.5.0")
		Expect(err).ToNot(HaveOccurred())
		Expect(string(content)).To(ContainSubstring(`NAME="Kairos"`))
		Expect(string(content)).To(ContainSubstring(`ID=kairos`))
		Expect(string(content)).To(ContainSubstring(`VERSION_ID=v3.5.0`))
		Expect(string(content)).To(ContainSubstring(`PRETTY_NAME="Kairos (v3.5.0)"`))
	})
})
