// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package pcr

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"github.com/google/go-tpm/tpm2"
	"github.com/kairos-io/go-ukify/pkg/constants"
	"github.com/kairos-io/go-ukify/pkg/types"
	"log/slog"
	"os"
)

// CalculateBankData calculates the PCR bank data for a given set of UKI file sections.
//
// This mimics the process happening in the TPM when the UKI is being loaded.
// Deprecated: Use MeasureSections + MeasurePhase + SignPolicy for more fine grained control
// Only used in teh tests to confirm that the new workflow returns the same data as the old one
func CalculateBankData(pcrNumber int, phases []types.PhaseInfo, alg tpm2.TPMAlgID, sectionData map[constants.Section]string, rsaKey types.RSAKey) ([]types.BankData, error) {
	// get fingerprint of public key
	pubKeyFingerprint := sha256.Sum256(x509.MarshalPKCS1PublicKey(rsaKey.PublicRSAKey()))

	hashAlg, err := alg.Hash()
	if err != nil {
		return nil, err
	}

	pcrSelector, err := CreateSelector([]int{pcrNumber})
	if err != nil {
		return nil, fmt.Errorf("failed to create PCR selection: %v", err)
	}

	pcrSelection := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      alg,
				PCRSelect: pcrSelector,
			},
		},
	}

	hashData := NewDigest(hashAlg)

	for _, section := range constants.OrderedSections() {
		if file := sectionData[section]; file != "" {
			slog.Debug("Measuring section", "section", section, "alg", hashAlg.String())

			sectionD, err := os.ReadFile(file)
			if err != nil {
				return nil, err
			}
			// NULL terminated, thats why we adding the 0 at the end
			hashData.Extend(append([]byte(section), 0))
			hashData.Extend(sectionD)
		}
	}

	banks := make([]types.BankData, 0)

	for _, phaseInfo := range phases {
		slog.Debug("Doing phase", "phase", phaseInfo.Phase, "alg", hashAlg.String())
		// extend always
		hashData.Extend([]byte(phaseInfo.Phase))

		hash := hashData.Hash()
		slog.Debug("Expected Hash calculated", "hash", hex.EncodeToString(hash), "alg", hashAlg.String(), "phase", phaseInfo.Phase)

		policyPCR, err := CalculatePolicy(hash, pcrSelection)

		if err != nil {
			return nil, err
		}

		sigData, err := Sign(policyPCR, hashAlg, rsaKey)
		if err != nil {
			return nil, err
		}

		slog.Debug("signed policy", "PKFP", hex.EncodeToString(pubKeyFingerprint[:]))
		slog.Debug("signed policy", "pol", sigData.Digest)
		slog.Debug("signed policy", "Sig", sigData.SignatureBase64)

		banks = append(banks, types.BankData{
			PCRs: []int{pcrNumber},
			PKFP: hex.EncodeToString(pubKeyFingerprint[:]),
			Sig:  sigData.SignatureBase64,
			Pol:  sigData.Digest,
		})

	}

	return banks, nil
}

// MeasureSections would measure the given sections for a given TPM algorithm
func MeasureSections(alg tpm2.TPMAlgID, sectionData map[constants.Section]string) (*Digest, error) {
	var hashData *Digest

	hashAlg, err := alg.Hash()
	if err != nil {
		return hashData, err
	}

	hashData = NewDigest(hashAlg)

	for _, section := range constants.OrderedSections() {
		if file := sectionData[section]; file != "" {
			slog.Debug("Measuring section", "section", section, "alg", hashAlg.String())

			sectionD, err := os.ReadFile(file)
			if err != nil {
				return hashData, err
			}
			// NULL terminated, thats why we adding the 0 at the end
			hashData.Extend(append([]byte(section), 0))
			hashData.Extend(sectionD)
		}
	}
	return hashData, nil
}

// MeasurePhase will measure the given phase
func MeasurePhase(phase types.PhaseInfo, alg tpm2.TPMAlgID, hashData *Digest) *Digest {
	hashAlg, _ := alg.Hash()

	// TODO: Allow passing the phases by config
	slog.Debug("Doing phase", "phase", phase.Phase, "alg", hashAlg.String())
	// extend always
	hashData.Extend([]byte(phase.Phase))

	hash := hashData.Hash()
	slog.Debug("Expected Hash calculated", "hash", hex.EncodeToString(hash), "alg", hashAlg.String(), "phase", phase.Phase)

	return hashData
}

// SignPolicy will calculate and sign a policy for a given Digest, PCR and algorithm
func SignPolicy(pcrNumber int, alg tpm2.TPMAlgID, rsaKey types.RSAKey, hashData *Digest) (types.BankData, error) {
	var bankData types.BankData
	hash := hashData.Hash()
	pubKeyFingerprint := sha256.Sum256(x509.MarshalPKCS1PublicKey(rsaKey.PublicRSAKey()))

	pcrSelector, err := CreateSelector([]int{pcrNumber})
	if err != nil {
		return bankData, fmt.Errorf("failed to create PCR selection: %v", err)
	}

	pcrSelection := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      alg,
				PCRSelect: pcrSelector,
			},
		},
	}

	policyPCR, err := CalculatePolicy(hash, pcrSelection)

	if err != nil {
		return bankData, err
	}

	hashAlg, err := alg.Hash()

	sigData, err := Sign(policyPCR, hashAlg, rsaKey)
	if err != nil {
		return bankData, err
	}

	slog.Debug("signed policy", "PKFP", hex.EncodeToString(pubKeyFingerprint[:]))
	slog.Debug("signed policy", "pol", sigData.Digest)
	slog.Debug("signed policy", "Sig", sigData.SignatureBase64)

	return types.BankData{
		PCRs: []int{pcrNumber},
		PKFP: hex.EncodeToString(pubKeyFingerprint[:]),
		Sig:  sigData.SignatureBase64,
		Pol:  sigData.Digest,
	}, nil

}

// CreateSelector converts PCR  numbers into a bitmask.
func CreateSelector(pcrs []int) ([]byte, error) {
	// From https://trustedcomputinggroup.org/resource/pc-client-platform-tpm-profile-ptp-specification/
	// A conformant TPM SHALL allow an allocation of a minimum of 24 PCRs, 0-23, within all allocated banks

	const sizeOfPCRSelect = 3

	mask := make([]byte, sizeOfPCRSelect)

	for _, n := range pcrs {
		if n >= 8*sizeOfPCRSelect {
			return nil, fmt.Errorf("PCR index %d is out of range (exceeds maximum value %d)", n, 8*sizeOfPCRSelect-1)
		}

		mask[n>>3] |= 1 << (n & 0x7)
	}

	return mask, nil
}

// CalculatePolicy calculates the policy hash for a given PCR value and PCR selection.
func CalculatePolicy(pcrValue []byte, pcrSelection tpm2.TPMLPCRSelection) ([]byte, error) {
	calculator, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		return nil, err
	}

	calculator.Reset()
	pcrHash := sha256.Sum256(pcrValue)

	policy := tpm2.PolicyPCR{
		PcrDigest: tpm2.TPM2BDigest{
			Buffer: pcrHash[:],
		},
		Pcrs: pcrSelection,
	}

	if err := policy.Update(calculator); err != nil {
		return nil, err
	}
	return calculator.Hash().Digest, nil
}
