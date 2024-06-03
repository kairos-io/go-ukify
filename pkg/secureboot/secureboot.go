// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package secureboot contains base definitions for the Secure Boot process.
package secureboot

import "github.com/itxaka/go-ukify/pkg/constants"

// OrderedSections returns the sections that are measured into PCR.
//
// Derived from https://github.com/systemd/systemd/blob/main/src/fundamental/tpm-pcr.h#L23-L36
// .pcrsig section is omitted here since that's what we are calulating here.
func OrderedSections() []constants.Section {
	// DO NOT REARRANGE
	return []constants.Section{
		constants.Linux,
		constants.OSRel,
		constants.CMDLine,
		constants.Initrd,
		constants.Splash,
		constants.DTB,
		constants.Uname,
		constants.SBAT,
		constants.PCRPKey}
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
			Phase:              constants.EnterMachined,
			CalculateSignature: true,
		},
	}
}
