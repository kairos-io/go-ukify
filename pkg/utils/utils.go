package utils

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"log/slog"

	"github.com/foxboron/go-uefi/authenticode"
	"github.com/foxboron/go-uefi/pkcs7"
	"github.com/kairos-io/go-ukify/pkg/constants"
	"github.com/kairos-io/go-ukify/pkg/types"
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

	sig, err := pkcs7.SignPKCS7(key, cert, authenticode.OIDSpcIndirectDataContent, pecoffBinary.Bytes())
	if err != nil {
		slog.Debug("failed to sign EFI binary", "error", err)
		return nil, err
	}

	err = pecoffBinary.AppendSignature(sig)
	if err != nil {
		slog.Debug("failed to append EFI binary signature", "error", err)
		return nil, err
	}
	return pecoffBinary.Bytes(), nil
}
