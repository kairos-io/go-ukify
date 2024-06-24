package pesign

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Pesign test Suite")
}

var _ = Describe("Pesign tests", func() {
	var sbSigner *Signer
	var tmpDir string

	BeforeEach(func() {
		sb, err := NewSecureBootSigner("testdata/sb.pem", "testdata/sb.key")
		Expect(err).ToNot(HaveOccurred())

		sbSigner, err = NewSigner(sb)
		Expect(err).ToNot(HaveOccurred())

		tmpDir, err = os.MkdirTemp("", "pesign")
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		Expect(os.RemoveAll(tmpDir)).ToNot(HaveOccurred())
	})
	Describe("Signs correctly a PE file", func() {
		It("Signs correctly a file", func() {
			err := sbSigner.Sign("testdata/file.efi", filepath.Join(tmpDir, "file.signed.efi"))
			Expect(err).ToNot(HaveOccurred())

		})

	})
})
