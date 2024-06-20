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
	"log"
	"log/slog"
	"os"

	"github.com/foxboron/go-uefi/efi"
	"github.com/kairos-io/go-ukify/pkg/measure"
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
func (s *Signer) Sign(input, output string, logger *slog.Logger) error {
	logger.Debug("Signing file", "input", input, "output", output)
	unsigned, err := os.ReadFile(input)
	if err != nil {
		log.Fatalf("Failed to open %s", input)
		return err
	}

	signed, err := efi.SignEFIExecutable(s.provider.Signer(), s.provider.Certificate(), unsigned)
	if err != nil {
		log.Fatalf("Failed to open %s", input)
		return err
	}

	return os.WriteFile(output, signed, 0o600)
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
var _ measure.RSAKey = (*PCRSigner)(nil)

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

	rsaKey, err := x509.ParsePKCS8PrivateKey(rsaPrivateKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private RSA key: %v", err)
	}

	rsaKeyParsed := rsaKey.(*rsa.PrivateKey)
	return &PCRSigner{rsaKeyParsed}, nil
}
