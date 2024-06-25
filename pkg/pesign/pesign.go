// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package pesign implements the PE (portable executable) signing.
package pesign

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/foxboron/go-uefi/authenticode"
	"github.com/kairos-io/go-ukify/pkg/types"
)

// Signer sigs PE (portable executable) files.
type Signer struct {
	provider CertificateSigner
}

// CertificateSigner is a provider of the certificate and the signer.
type CertificateSigner interface {
	Signer() crypto.Signer
	Certificate() *x509.Certificate
}

// NewSigner creates a new Signer.
func NewSigner(provider CertificateSigner) (*Signer, error) {
	return &Signer{
		provider: provider,
	}, nil
}

// Sign signs the input file and writes the output to the output file.
func (s *Signer) Sign(input, output string) error {
	if _, err := os.Stat(input); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s does not exist", input)
	}
	slog.Debug("Signing file", "input", input, "output", output)

	si, err := os.Stat(input)
	if err != nil {
		return fmt.Errorf("failed getting input file info: %w", err)
	}

	ok, err := s.VerifyFile(input)
	if ok {
		slog.Warn("File is already signed with the cert, copying it into output file")
		// already signed with the cert
		// just copy it to the output place
		f, err := os.ReadFile(input)
		if err != nil {
			return fmt.Errorf("failed reading input file: %w", err)
		}
		if err = os.WriteFile(output, f, si.Mode()); err != nil {
			return fmt.Errorf("failed writing output file: %w", err)
		}
		return nil
	}

	peFile, err := os.Open(input)
	if err != nil {
		return err
	}
	defer peFile.Close()

	peBinary, err := authenticode.Parse(peFile)
	if err != nil {
		return err
	}

	_, err = peBinary.Sign(s.provider.Signer(), s.provider.Certificate())
	if err != nil {
		return err
	}

	if err = os.WriteFile(output, peBinary.Bytes(), si.Mode()); err != nil {
		return err
	}

	// Now verify the output just in case
	ok, err = s.VerifyFile(output)
	if !ok || err != nil {
		return fmt.Errorf("failed verifying output file: %w", err)
	}

	return nil
}

func (s *Signer) VerifyFile(file string) (bool, error) {
	peFile, err := os.Open(file)
	if err != nil {
		return false, err
	}
	defer peFile.Close()

	peBinary, err := authenticode.Parse(peFile)
	if err != nil {
		return false, err
	}

	sigs, err := peBinary.Signatures()
	if err != nil {
		return false, fmt.Errorf("%s: %w", file, err)
	}

	if len(sigs) == 0 {
		return false, nil
	}

	return peBinary.Verify(s.provider.Certificate())
}

// Verify interface.
var _ CertificateSigner = (*SecureBootSigner)(nil)

// Signer returns the signer.
func (s *SecureBootSigner) Signer() crypto.Signer {
	return s.key
}

// Certificate returns the certificate.
func (s *SecureBootSigner) Certificate() *x509.Certificate {
	return s.cert
}

// SecureBootSigner implements pesign.CertificateSigner interface.
type SecureBootSigner struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

func NewSecureBootSigner(certPath, keyPath string) (*SecureBootSigner, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	// convert private key to rsa.PrivateKey
	rsaPrivateKeyBlock, _ := pem.Decode(keyData)
	if rsaPrivateKeyBlock == nil {
		return nil, errors.New("failed to decode private key")
	}

	rsaKey, err := x509.ParsePKCS8PrivateKey(rsaPrivateKeyBlock.Bytes)
	rsaKeyParsed := rsaKey.(*rsa.PrivateKey)

	if err != nil {
		return nil, fmt.Errorf("failed to parse private RSA key: %w", err)
	}

	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return nil, errors.New("failed to decode certificate")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return &SecureBootSigner{
		key:  rsaKeyParsed,
		cert: cert,
	}, nil
}

// SigningKeyAndCertificate describes a signing key & certificate.
type SigningKeyAndCertificate struct {
	// File-based.
	//
	// Static key and certificate paths.
	KeyPath  string `yaml:"keyPath,omitempty"`
	CertPath string `yaml:"certPath,omitempty"`
}

// PCRSigner implements measure.RSAKey interface.
type PCRSigner struct {
	key *rsa.PrivateKey
}

// Verify interface.
var _ types.RSAKey = (*PCRSigner)(nil)

// PublicRSAKey returns the public key.
func (s *PCRSigner) PublicRSAKey() *rsa.PublicKey {
	return &s.key.PublicKey
}

// Public returns the public key.
func (s *PCRSigner) Public() crypto.PublicKey {
	return s.PublicRSAKey()
}

// Sign implements the crypto.Signer interface.
func (s *PCRSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return s.key.Sign(rand, digest, opts)
}

// NewPCRSigner creates a new PCR signer from the private key file.
func NewPCRSigner(keyPath string) (*PCRSigner, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	// convert private key to rsa.PrivateKey
	rsaPrivateKeyBlock, _ := pem.Decode(keyData)
	if rsaPrivateKeyBlock == nil {
		return nil, errors.New("failed to decode private key")
	}

	var rsaKey *rsa.PrivateKey
	rsaKey, err = x509.ParsePKCS1PrivateKey(rsaPrivateKeyBlock.Bytes)
	if err != nil {
		// Try to see if its in a different format maybe?
		key, err := x509.ParsePKCS8PrivateKey(rsaPrivateKeyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private RSA key: %v", err)
		}
		rsaKey = key.(*rsa.PrivateKey)
	}

	//rsaKeyParsed := rsaKey.(*rsa.PrivateKey)
	return &PCRSigner{rsaKey}, nil
}
