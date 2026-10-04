package pesign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The Secure Boot key and the PCR key are the same kind of key material, so a
// key one signer loads has to be a key the other loads too. Each signer used to
// read it its own way: --pcr-key took PKCS#1 and PKCS#8, --sb-key took PKCS#8
// only, and --pcr-key panicked on a PKCS#8 key that was not RSA.
var _ = Describe("Private key loading", func() {
	var tmpDir string
	var certPath string
	var rsaKey *rsa.PrivateKey

	writePEM := func(name, blockType string, der []byte) string {
		path := filepath.Join(tmpDir, name)
		Expect(os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600)).To(Succeed())
		return path
	}

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "pesign-keys")
		Expect(err).ToNot(HaveOccurred())
		DeferCleanup(func() { Expect(os.RemoveAll(tmpDir)).To(Succeed()) })

		rsaKey, err = rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).ToNot(HaveOccurred())

		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "Kairos Test DB"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
		Expect(err).ToNot(HaveOccurred())
		certPath = writePEM("cert.pem", "CERTIFICATE", der)
	})

	// `openssl genrsa` writes PKCS#1 on OpenSSL 1.x, so a lot of Secure Boot key
	// material already on disk is in that encoding.
	It("loads a PKCS#1 key into both signers", func() {
		path := writePEM("pkcs1.pem", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey))

		sb, err := NewSecureBootSigner(certPath, path)
		Expect(err).ToNot(HaveOccurred())
		Expect(sb.Signer()).To(Equal(rsaKey))

		pcr, err := NewPCRSigner(path)
		Expect(err).ToNot(HaveOccurred())
		Expect(pcr.PublicRSAKey()).To(Equal(&rsaKey.PublicKey))
	})

	// `openssl genpkey` and OpenSSL 3 write PKCS#8.
	It("loads a PKCS#8 key into both signers", func() {
		der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
		Expect(err).ToNot(HaveOccurred())
		path := writePEM("pkcs8.pem", "PRIVATE KEY", der)

		sb, err := NewSecureBootSigner(certPath, path)
		Expect(err).ToNot(HaveOccurred())
		Expect(sb.Signer()).To(Equal(rsaKey))

		pcr, err := NewPCRSigner(path)
		Expect(err).ToNot(HaveOccurred())
		Expect(pcr.PublicRSAKey()).To(Equal(&rsaKey.PublicKey))
	})

	// An EC key is a valid PKCS#8 key, so it parses and only then turns out to
	// be the wrong type. Both signers have to say so instead of panicking.
	It("reports a key that is not RSA, for both signers", func() {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).ToNot(HaveOccurred())
		der, err := x509.MarshalPKCS8PrivateKey(ecKey)
		Expect(err).ToNot(HaveOccurred())
		path := writePEM("ec.pem", "PRIVATE KEY", der)

		_, err = NewSecureBootSigner(certPath, path)
		Expect(err).To(MatchError(ContainSubstring("not an RSA key")))

		_, err = NewPCRSigner(path)
		Expect(err).To(MatchError(ContainSubstring("not an RSA key")))
	})

	It("reports a file that is not PEM at all", func() {
		path := filepath.Join(tmpDir, "garbage.pem")
		Expect(os.WriteFile(path, []byte("not a key"), 0o600)).To(Succeed())

		_, err := NewSecureBootSigner(certPath, path)
		Expect(err).To(MatchError(ContainSubstring("failed to decode private key")))

		_, err = NewPCRSigner(path)
		Expect(err).To(MatchError(ContainSubstring("failed to decode private key")))
	})
})
