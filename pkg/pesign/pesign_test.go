package pesign

import (
	"github.com/foxboron/go-uefi/authenticode"
	"github.com/foxboron/go-uefi/pkcs7"
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
			// Check first that the base input has no signatures
			f1, err := os.Open("testdata/file.efi")
			Expect(err).ToNot(HaveOccurred())
			binary, err := authenticode.Parse(f1)
			defer f1.Close()
			signatures, err := binary.Signatures()
			Expect(err).ToNot(HaveOccurred())
			Expect(signatures).To(HaveLen(0))

			// Now we can continue signing and checking if the final file is signed
			err = sbSigner.Sign("testdata/file.efi", filepath.Join(tmpDir, "file.signed.efi"))
			Expect(err).ToNot(HaveOccurred())
			f2, err := os.Open(filepath.Join(tmpDir, "file.signed.efi"))
			Expect(err).ToNot(HaveOccurred())
			defer f2.Close()
			binary, err = authenticode.Parse(f2)
			Expect(err).ToNot(HaveOccurred())
			signatures, err = binary.Signatures()
			Expect(err).ToNot(HaveOccurred())
			Expect(signatures).To(HaveLen(1))
			for _, signature := range signatures {
				parsedPKCS7, err := pkcs7.ParsePKCS7(signature.Certificate)
				Expect(err).ToNot(HaveOccurred())
				// Expect the signatures in the signed file to match our key/cert issuer
				Expect(parsedPKCS7.Certs[0].Issuer.CommonName).To(Equal("Kairos DB"))
				Expect(parsedPKCS7.Certs[0].Subject.CommonName).To(Equal("Kairos DB"))
			}

		})

	})
})
