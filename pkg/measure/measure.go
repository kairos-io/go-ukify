// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package measure contains Go implementation of 'systemd-measure' command.
//
// This implements TPM PCR emulation, UKI signature measurement, signing the measured values.
package measure

import (
	"encoding/hex"
	"fmt"
	"github.com/kairos-io/go-ukify/pkg/constants"
	"github.com/kairos-io/go-ukify/pkg/measure/pcr"
	"github.com/kairos-io/go-ukify/pkg/types"
	"log/slog"
	"os/exec"
	"regexp"
)

// SectionsData holds a map of Section to file path to the corresponding section.
type SectionsData map[constants.Section]string

// GenerateSignedPCR generates the PCR signed data for a given set of UKI file sections.
func GenerateSignedPCR(sectionsData SectionsData, phases []types.PhaseInfo, rsaKey types.RSAKey, PCR int, logger *slog.Logger) (*types.PCRData, error) {
	data := &types.PCRData{}
	logger.Debug("Generating PCR data", "sections", sectionsData)

	data, algos := types.GetTPMALGorithm()
	for _, alg := range algos {
		banks := make([]types.BankData, 0)
		hash, err := pcr.MeasureSections(alg.Alg, sectionsData)
		if err != nil {
			return nil, err
		}
		for _, phase := range phases {
			hash = pcr.MeasurePhase(phase, alg.Alg, hash)
			bank, err := pcr.SignPolicy(PCR, alg.Alg, rsaKey, hash)
			if err != nil {
				return nil, err
			}
			banks = append(banks, bank)
		}
		*alg.BankDataSetter = banks
	}

	return data, nil
}

// GenerateMeasurements generates the PCR measurements for a given set of UKI file sections and phases
func GenerateMeasurements(sectionsData SectionsData, phases []types.PhaseInfo, PCR int, logger *slog.Logger) {
	logger.Debug("Generating PCR data", "sections", sectionsData)
	logger.Info("Not signing data, just outputting it to stdout")
	logger.Info("legend: <PHASE:PCR:ALGORITHM=HASH>")

	_, algos := types.GetTPMALGorithm()
	for _, alg := range algos {
		hash, _ := pcr.MeasureSections(alg.Alg, sectionsData)
		for _, phase := range phases {
			pcr.MeasurePhase(phase, alg.Alg, hash)
			al, _ := alg.Alg.Hash()
			logger.Info(fmt.Sprintf("%s:%d:%s=%s", phase.Phase, PCR, al.String(), hex.EncodeToString(hash.Hash())))
		}

	}
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
