package pki_test

import (
	"crypto/x509"
	"encoding/pem"
	"path/filepath"

	"github.com/KibaFox/tls-usr-sessions/pki"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("PKI", func() {
	It("Should be able to generate a new private key", func() {
		key, err := pki.GenerateKey()
		Expect(err).ToNot(HaveOccurred())
		Expect(key).ShouldNot(BeNil())
	})

	It("Should be able to save + load a private key", func() {
		dir := tmpDir()
		defer rmDir(dir)
		file := filepath.Join(dir, "mykey.pem")

		key, err := pki.GenerateKey()
		Expect(err).ToNot(HaveOccurred())

		err = pki.SaveKey(key, file)
		Expect(err).ToNot(HaveOccurred())
		Expect(file).Should(BeARegularFile())

		loadedKey, err := pki.LoadKey(file)
		Expect(err).ToNot(HaveOccurred())
		Expect(loadedKey).Should(Equal(key))
	})

	It("Can create a CSR", func() {
		key, err := pki.GenerateKey()
		Expect(err).ToNot(HaveOccurred())

		csrPEM, err := pki.NewCSR(key, "silly common name")
		Expect(err).ToNot(HaveOccurred())
		Expect(csrPEM).ShouldNot(BeEmpty())

		blk, _ := pem.Decode([]byte(csrPEM))
		Expect(blk).ToNot(BeNil())
		Expect(blk.Type).Should(Equal("CERTIFICATE REQUEST"))

		csr, err := x509.ParseCertificateRequest(blk.Bytes)
		Expect(err).ToNot(HaveOccurred())
		Expect(csr.Subject.CommonName).Should(Equal("silly common name"))
		Expect(csr.CheckSignature()).To(Succeed())
		Expect(csr.PublicKey).Should(Equal(&key.PublicKey))
	})

	PIt("Can sign a CSR", func() {
		// TODO
	})

	PIt("Can create a self-signed certificate", func() {
		// TODO
	})
})
