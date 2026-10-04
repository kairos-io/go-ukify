// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package uki

import (
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/kairos-io/go-ukify/pkg/pesign"
)

const (
	testSBKey  = "../pesign/testdata/sb.key"
	testSBCert = "../pesign/testdata/sb.pem"
)

var _ = Describe("Build with a Secure Boot pair", func() {
	var outUKI, outUnsigned string

	// newBuilder returns a builder whose only interesting property is its
	// Secure Boot configuration. Everything else is deliberately unset, so a
	// build that gets past the pair check fails on a later, different error.
	newBuilder := func() *Builder {
		return &Builder{OutUKIPath: outUKI}
	}

	BeforeEach(func() {
		dir := GinkgoT().TempDir()
		// The CLI default, which is also what makes the skip-signing branch
		// rewrite the name instead of overwriting the requested path.
		outUKI = filepath.Join(dir, "uki.signed.efi")
		outUnsigned = filepath.Join(dir, "uki.unsigned.efi")
	})

	When("only the key is given", func() {
		It("refuses the build and writes nothing", func() {
			builder := newBuilder()
			builder.SBKey = testSBKey

			err := builder.Build()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("secure boot key given without a certificate"))

			// Neither at the requested path nor at the one the skip-signing
			// branch would have used.
			Expect(outUKI).ToNot(BeAnExistingFile())
			Expect(outUnsigned).ToNot(BeAnExistingFile())
		})
	})

	When("only the certificate is given", func() {
		It("refuses the build and writes nothing", func() {
			builder := newBuilder()
			builder.SBCert = testSBCert

			err := builder.Build()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("secure boot certificate given without a key"))

			Expect(outUKI).ToNot(BeAnExistingFile())
			Expect(outUnsigned).ToNot(BeAnExistingFile())
		})
	})

	When("neither is given", func() {
		It("is an unsigned build, so the check lets it through", func() {
			// It still fails, on the sections it has no inputs for, but it
			// has to get past the pair check to fail there.
			err := newBuilder().Build()

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).ToNot(ContainSubstring("secure boot"))
		})
	})

	When("both are given", func() {
		It("is a signing build, so the check lets it through", func() {
			builder := newBuilder()
			builder.SBKey = testSBKey
			builder.SBCert = testSBCert

			err := builder.Build()

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).ToNot(ContainSubstring("given without"))
		})
	})

	When("a signer is supplied directly", func() {
		It("does not need the key and certificate fields", func() {
			sb, err := pesign.NewSecureBootSigner(testSBCert, testSBKey)
			Expect(err).ToNot(HaveOccurred())
			signer, err := pesign.NewSigner(sb)
			Expect(err).ToNot(HaveOccurred())

			builder := newBuilder()
			builder.SecureBootSigner = signer
			builder.SBKey = testSBKey

			err = builder.Build()

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).ToNot(ContainSubstring("secure boot"))
		})
	})
})
