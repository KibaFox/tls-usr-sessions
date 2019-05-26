package pki_test

import (
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"time"

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
		Expect(csr.SignatureAlgorithm).Should(Equal(x509.ECDSAWithSHA256))
		Expect(csr.Subject.CommonName).Should(Equal("silly common name"))
		Expect(csr.CheckSignature()).To(Succeed())
		Expect(csr.PublicKey).Should(Equal(&key.PublicKey))
	})

	PIt("Can sign a CSR", func() {
		// TODO
	})

	It("Can create a self-signed certificate", func() {
		key, err := pki.GenerateKey()
		Expect(err).ToNot(HaveOccurred())

		certPEM, err := pki.SelfSign(key, "good authority")
		Expect(err).ToNot(HaveOccurred())
		Expect(certPEM).ToNot(BeEmpty())

		blk, _ := pem.Decode([]byte(certPEM))
		Expect(blk).ToNot(BeNil())
		Expect(blk.Type).Should(Equal("CERTIFICATE"))

		cert, err := x509.ParseCertificate(blk.Bytes)
		Expect(err).ToNot(HaveOccurred())
		Expect(cert.Subject.CommonName).Should(Equal("good authority"))
		Expect(cert.SignatureAlgorithm).Should(Equal(x509.ECDSAWithSHA256))
		Expect(cert.IsCA).Should(BeTrue(), "self-signed cert should be CA")
		Expect(cert.MaxPathLen).Should(BeZero())
		Expect(cert.MaxPathLenZero).Should(BeTrue())
		Expect(cert.KeyUsage).Should(Equal(
			x509.KeyUsageKeyEncipherment |
				x509.KeyUsageDigitalSignature |
				x509.KeyUsageCertSign))
		Expect(cert.ExtKeyUsage).Should(Equal([]x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		}))
		Expect(cert.NotBefore).Should(
			BeTemporally("~", time.Now(), time.Second))
		Expect(cert.NotAfter).Should(
			BeTemporally("~", time.Now().AddDate(5, 0, 0), time.Second))
	})
})
