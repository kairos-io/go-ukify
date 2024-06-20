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
	"github.com/kairos-io/go-ukify/pkg/constants"
	"github.com/kairos-io/go-ukify/pkg/measure/pcr"
	"github.com/kairos-io/go-ukify/pkg/types"
	"log/slog"
	"os/exec"
	"regexp"
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

func PrintSystemdMeasurements(phase string, sectionsData SectionsData, privKey string) {
	args := []string{
		"--cmdline", sectionsData[constants.CMDLine],
		"--initrd", sectionsData[constants.Initrd],
		"--linux", sectionsData[constants.Linux],
		"--osrel", sectionsData[constants.OSRel],
		"--pcrpkey", sectionsData[constants.PCRPKey],
		"--sbat", sectionsData[constants.SBAT],
		"--uname", sectionsData[constants.Uname],
		"--splash", sectionsData[constants.Splash],
		"--phase", phase,
		"--private-key", privKey,
		"--bank", "SHA256",
		"--json=short"}

	slog.Debug("using the following contents for measurements",
		"cmdline", sectionsData[constants.CMDLine],
		"initrd", sectionsData[constants.Initrd],
		"linux", sectionsData[constants.Linux],
		"osrel", sectionsData[constants.OSRel],
		"sbat", sectionsData[constants.SBAT],
		"pcrpkey", sectionsData[constants.PCRPKey],
		"uname", sectionsData[constants.Uname],
		"--splash", sectionsData[constants.Splash],
	)

	// First log the hash we got from the final phase
	cmd := exec.Command("/usr/lib/systemd/systemd-measure", append([]string{"calculate"}, args...)...)
	out, _ := cmd.CombinedOutput()
	r, _ := regexp.Compile(`hash":"([\w|\d].*)"`)
	match := r.Find(out)
	slog.Debug("measure output", "match", match, "phase", phase)
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
