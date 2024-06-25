package utils

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"github.com/foxboron/go-uefi/authenticode"
	"github.com/kairos-io/go-ukify/pkg/constants"
	"github.com/kairos-io/go-ukify/pkg/types"
	"log/slog"
)

// SectionsData transforms a []types.UkiSection into a map[constants.Section]string
// based on types.UkiSection.Measure being true
// So it obtains a list of sections that have to be measured
func SectionsData(sections []types.UkiSection) map[constants.Section]string {
	data := map[constants.Section]string{}
	for _, s := range sections {
		if s.Measure {
			data[s.Name] = s.Path
		}
	}
	// Mimic what xslices does if there is no data, we return nil
	if len(data) == 0 {
		return nil
	}
	return data
}

// SignEFIExecutable signs an executable
// go-uefi dropped this but they still all of the methods needed to sign an executable
func SignEFIExecutable(key crypto.Signer, cert *x509.Certificate, file []byte) ([]byte, error) {
	pecoffBinary, err := authenticode.Parse(bytes.NewReader(file))
	if err != nil {
		slog.Debug("failed to parse EFI binary", "error", err)
		return nil, err
	}

	signedFile, err := pecoffBinary.Sign(key, cert)
	if err != nil {
		return nil, err
	}

	// Verify it
	verify, err := pecoffBinary.Verify(cert)
	if !verify {
		return nil, errors.New("failed to verify")
	}

	return signedFile, nil
}
