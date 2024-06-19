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
	"encoding/json"
	"github.com/google/go-tpm/tpm2"
	"github.com/itxaka/go-ukify/pkg/constants"
	"github.com/itxaka/go-ukify/pkg/measure/pcr"
	"github.com/itxaka/go-ukify/pkg/types"
	"log/slog"
	"os/exec"
)

// SectionsData holds a map of Section to file path to the corresponding section.
type SectionsData map[constants.Section]string

// RSAKey is the input for the CalculateBankData function.
type RSAKey interface {
	crypto.Signer
	PublicRSAKey() *rsa.PublicKey
}

// GenerateSignedPCR generates the PCR signed data for a given set of UKI file sections.
func GenerateSignedPCR(sectionsData SectionsData, rsaKey RSAKey, PCR int, logger *slog.Logger) (*types.PCRData, error) {
	data := &types.PCRData{}
	logger.Debug("Generating PCR data", "sections", sectionsData)

	for _, algo := range []struct {
		alg            tpm2.TPMAlgID
		bankDataSetter *[]types.BankData
	}{
		{
			alg:            tpm2.TPMAlgSHA1,
			bankDataSetter: &data.SHA1,
		},
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
		bankData, err := pcr.CalculateBankData(PCR, algo.alg, sectionsData, rsaKey)
		if err != nil {
			return nil, err
		}

		*algo.bankDataSetter = bankData
	}

	return data, nil
}

func CheckSignedMeasurementsAgainstSystemd(sectionsData SectionsData, privKey string, measurements *types.PCRData) {
	args := []string{
		"--cmdline", sectionsData[constants.CMDLine],
		"--initrd", sectionsData[constants.Initrd],
		"--linux", sectionsData[constants.Linux],
		"--osrel", sectionsData[constants.OSRel],
		"--pcrpkey", sectionsData[constants.PCRPKey],
		"--sbat", sectionsData[constants.SBAT],
		"--uname", sectionsData[constants.Uname],
		"--phase", "enter-initrd:leave-initrd:sysinit:ready",
		"--private-key", privKey,
		"--bank", "SHA256",
		"--json=short"}

	type Calculate struct {
		Sha256 []struct {
			Phase string `json:"phase"`
			Pcr   int    `json:"pcr"`
			Hash  string `json:"hash"`
		} `json:"sha256"`
	}

	type Sign struct {
		Sha256 []struct {
			Pcrs []int  `json:"pcrs"`
			Pkfp string `json:"pkfp"`
			Pol  string `json:"pol"`
			Sig  string `json:"sig"`
		} `json:"sha256"`
	}

	// First log the hash we got from the final phase
	cmd := exec.Command("/usr/lib/systemd/systemd-measure", append([]string{"calculate"}, args...)...)
	out, _ := cmd.CombinedOutput()
	outputCalculate := Calculate{}
	json.Unmarshal(out, &outputCalculate)
	slog.Debug("measure calculate output", "out", outputCalculate.Sha256[0].Hash)

	cmd = exec.Command("/usr/lib/systemd/systemd-measure", append([]string{"sign"}, args...)...)
	out, _ = cmd.CombinedOutput()
	outPut := Sign{}
	json.Unmarshal(out, &outPut)
	slog.Debug("measure sign output", "PKFP", outPut.Sha256[0].Pkfp)
	slog.Debug("measure sign output", "pol", outPut.Sha256[0].Pol)
	slog.Debug("measure sign output", "Sig", outPut.Sha256[0].Sig)
	if measurements.SHA256[0].Sig != outPut.Sha256[0].Sig {

	}
}

// GenerateSignedPCRForBytes generates the PCR signed data for a given file
func GenerateSignedPCRForBytes(file string, rsaKey RSAKey, PCR int) (*types.PCRData, error) {
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
		bankData, err := pcr.CalculateBankDataForFile(PCR, algo.alg, file, rsaKey)
		if err != nil {
			return nil, err
		}

		*algo.bankDataSetter = bankData
	}

	return data, nil
}
