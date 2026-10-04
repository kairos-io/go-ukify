package pcr

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"

	"github.com/google/go-tpm/tpm2"
	"github.com/kairos-io/go-ukify/pkg/constants"
	"github.com/kairos-io/go-ukify/pkg/pesign"
	"github.com/kairos-io/go-ukify/pkg/types"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// verifyAsSystemdDoes checks a bank entry the way tpm2_policy_authorize() in
// systemd's src/shared/tpm2-util.c does at unseal time: SHA-256 over the
// policy digest, then RSASSA with TPM2_ALG_SHA256 declared in the
// TPMT_SIGNATURE handed to Esys_VerifySignature.
func verifyAsSystemdDoes(bank types.BankData, key *pesign.PCRSigner) error {
	pol, err := hex.DecodeString(bank.Pol)
	if err != nil {
		return err
	}

	sig, err := base64.StdEncoding.DecodeString(bank.Sig)
	if err != nil {
		return err
	}

	hashed := crypto.SHA256.New()
	hashed.Write(pol)

	return rsa.VerifyPKCS1v15(key.PublicRSAKey(), crypto.SHA256, hashed.Sum(nil), sig)
}

var _ = Describe("Policy signatures", func() {
	var signer *pesign.PCRSigner
	var sections map[constants.Section]string

	banks := []tpm2.TPMAlgID{
		tpm2.TPMAlgSHA1,
		tpm2.TPMAlgSHA256,
		tpm2.TPMAlgSHA384,
		tpm2.TPMAlgSHA512,
	}

	BeforeEach(func() {
		var err error
		signer, err = pesign.NewPCRSigner("testdata/private.pem")
		Expect(err).ToNot(HaveOccurred())
		sections = map[constants.Section]string{}
	})

	It("signs every bank so systemd can verify it", func() {
		for _, alg := range banks {
			name, err := alg.Hash()
			Expect(err).ToNot(HaveOccurred())

			hash, err := MeasureSections(alg, sections)
			Expect(err).ToNot(HaveOccurred())

			for _, phase := range types.OrderedPhases() {
				hash = MeasurePhase(phase, alg, hash)
				bank, err := SignPolicy(11, alg, signer, hash)
				Expect(err).ToNot(HaveOccurred())
				Expect(verifyAsSystemdDoes(bank, signer)).To(Succeed(),
					"bank %s, phase %s", name.String(), phase.Phase)
			}
		}
	})

	It("signs every bank the same way on the deprecated path", func() {
		for _, alg := range banks {
			name, err := alg.Hash()
			Expect(err).ToNot(HaveOccurred())

			banksData, err := CalculateBankData(11, types.OrderedPhases(), alg, sections, signer)
			Expect(err).ToNot(HaveOccurred())
			Expect(banksData).To(HaveLen(len(types.OrderedPhases())))

			for _, bank := range banksData {
				Expect(verifyAsSystemdDoes(bank, signer)).To(Succeed(), "bank %s", name.String())
			}
		}
	})

	It("leaves the sha256 bank's policy digests untouched", func() {
		hash, err := MeasureSections(tpm2.TPMAlgSHA256, sections)
		Expect(err).ToNot(HaveOccurred())

		pols := []string{}
		for _, phase := range types.OrderedPhases() {
			hash = MeasurePhase(phase, tpm2.TPMAlgSHA256, hash)
			bank, err := SignPolicy(11, tpm2.TPMAlgSHA256, signer, hash)
			Expect(err).ToNot(HaveOccurred())
			pols = append(pols, bank.Pol)
		}

		Expect(pols).To(Equal([]string{
			knowPCR11PolicyHashFirstPhase,
			knowPCR11PolicyHashSecondPhase,
			knowPCR11PolicyHashThirdPhase,
			knowPCR11PolicyHashFourthPhase,
		}))
	})
})
