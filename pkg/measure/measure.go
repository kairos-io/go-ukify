// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package measure contains Go implementation of 'systemd-measure' command.
//
// This implements TPM PCR emulation, UKI signature measurement, signing the measured values.
package measure

import (
	"crypto"
	"crypto/rsa"

	"github.com/google/go-tpm/tpm2"
	"github.com/itxaka/go-ukify/pkg/constants"
	"github.com/itxaka/go-ukify/pkg/measure/pcr"
	"github.com/itxaka/go-ukify/pkg/types"
)

// SectionsData holds a map of Section to file path to the corresponding section.
type SectionsData map[constants.Section]string

// RSAKey is the input for the CalculateBankData function.
type RSAKey interface {
	crypto.Signer
	PublicRSAKey() *rsa.PublicKey
}

// GenerateSignedPCR generates the PCR signed data for a given set of UKI file sections.
func GenerateSignedPCR(sectionsData SectionsData, rsaKey RSAKey) (*types.PCRData, error) {
	data := &types.PCRData{}

	for _, algo := range []struct {
		alg            tpm2.TPMAlgID
		bankDataSetter *[]types.BankData
	}{
		{
			alg:            tpm2.TPMAlgSHA256,
			bankDataSetter: &data.SHA256,
		},
		{
			alg:            tpm2.TPMAlgSHA384,
			bankDataSetter: &data.SHA384,
		},
		{
			alg:            tpm2.TPMAlgSHA512,
			bankDataSetter: &data.SHA512,
		},
	} {
		bankData, err := pcr.CalculateBankData(constants.UKIPCR, algo.alg, sectionsData, rsaKey)
		if err != nil {
			return nil, err
		}

		*algo.bankDataSetter = bankData
	}

	return data, nil
}
