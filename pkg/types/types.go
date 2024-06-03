package types

import "github.com/itxaka/go-ukify/pkg/constants"

// PCRData is the data structure for PCR signature json.
type PCRData struct {
	SHA1   []BankData `json:"sha1,omitempty"`
	SHA256 []BankData `json:"sha256,omitempty"`
	SHA384 []BankData `json:"sha384,omitempty"`
	SHA512 []BankData `json:"sha512,omitempty"`
}

// BankData constains data for a specific PCR bank.
type BankData struct {
	// list of PCR banks
	PCRs []int `json:"pcrs"`
	// Public key of the TPM
	PKFP string `json:"pkfp"`
	// Policy digest
	Pol string `json:"pol"`
	// Signature of the policy digest in base64
	Sig string `json:"sig"`
}

// PhaseInfo describes which phase extensions are signed/measured.
type PhaseInfo struct {
	Phase              constants.Phase
	CalculateSignature bool
}

// OrderedPhases returns the phases that are measured, in order.
//
// Derived from https://github.com/systemd/systemd/blob/v253/src/boot/measure.c#L295-L308
// ref: https://www.freedesktop.org/software/systemd/man/systemd-pcrphase.service.html#Description
//
// OrderedPhases returns the phases that are measured.
// It should be ok to measure only enter and leave as we unlock before that?
func OrderedPhases() []PhaseInfo {
	// DO NOT REARRANGE
	return []PhaseInfo{
		{
			Phase:              constants.EnterInitrd,
			CalculateSignature: false,
		},
		{
			Phase:              constants.LeaveInitrd,
			CalculateSignature: false,
		},
		{
			Phase:              constants.SysInit,
			CalculateSignature: true,
		},
		{
			Phase:              constants.Ready,
			CalculateSignature: true,
		},
	}
}