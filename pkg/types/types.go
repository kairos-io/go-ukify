package types

import (
	"crypto"
	"crypto/rsa"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/kairos-io/go-ukify/pkg/constants"
)

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

type Algorithm struct {
	Alg            tpm2.TPMAlgID
	BankDataSetter *[]BankData
}

func GetTPMALGorithm() (*PCRData, []Algorithm) {
	data := &PCRData{}
	algs := []Algorithm{
		{
			Alg:            tpm2.TPMAlgSHA1,
			BankDataSetter: &data.SHA1,
		},
		{
			Alg:            tpm2.TPMAlgSHA256,
			BankDataSetter: &data.SHA256,
		},
		{
			Alg:            tpm2.TPMAlgSHA384,
			BankDataSetter: &data.SHA384,
		},
		{
			Alg:            tpm2.TPMAlgSHA512,
			BankDataSetter: &data.SHA512,
		},
	}
	return data, algs
}

// PhaseInfo describes which phase extensions are signed/measured.
type PhaseInfo struct {
	Phase constants.Phase
}

// OrderedPhases returns the phases that are measured, in order.
//
// Derived from https://github.com/systemd/systemd/blob/v253/src/boot/measure.c#L295-L308
// ref: https://www.freedesktop.org/software/systemd/man/systemd-pcrphase.service.html#Description
//
// This means that for each phase the values will be measured at that point, so we want to cover all points
// If you custom extend the PCR with your own phases, the this is useless
// I.E. You want to load something and then extend so its measured up to that point, then the values below do
// not work for you
// OrderedPhases returns the phases that are measured.
func OrderedPhases() []PhaseInfo {
	// DO NOT REARRANGE
	return []PhaseInfo{
		{
			Phase: constants.EnterInitrd,
		},
		{
			Phase: constants.LeaveInitrd,
		},
		{
			Phase: constants.SysInit,
		},
		{
			Phase: constants.Ready,
		},
	}
}

// PhasesToString returns a nice string for all the phases with semicolons between them
func PhasesToString(s []PhaseInfo) string {
	var data []string
	for _, a := range s {
		data = append(data, string(a.Phase))
	}
	return strings.Join(data, ":")
}

// UkiSection is a UKI file section.
type UkiSection struct {
	// Section name.
	Name constants.Section
	// Path to the contents of the section.
	Path string
	// Should the section be measured to the TPM?
	Measure bool
	// Should the section be appended, or is it already in the PE file.
	Append bool
	// Size & VMA of the section.
	Size uint64
	VMA  uint64
}

// RSAKey is the input for the CalculateBankData function.
type RSAKey interface {
	crypto.Signer
	PublicRSAKey() *rsa.PublicKey
}
