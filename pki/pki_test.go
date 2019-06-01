package pki_test

import (
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/KibaFox/tls-usr-sessions/pki"
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

	It("Can sign a CSR", func() {
		By("Generating a new server key")
		srvKey, err := pki.GenerateKey()
		Expect(err).ToNot(HaveOccurred())

		By("Self signing a server CA certificate")
		srvCertPEM, err := pki.SelfSign(srvKey, "server")
		Expect(err).ToNot(HaveOccurred())

		blk, _ := pem.Decode([]byte(srvCertPEM))
		Expect(blk).ToNot(BeNil())
		srvCert, err := x509.ParseCertificate(blk.Bytes)
		Expect(err).ToNot(HaveOccurred())

		By("Generating a new client key")
		cliKey, err := pki.GenerateKey()
		Expect(err).ToNot(HaveOccurred())

		By("Creating a new CSR for the client")
		csrPEM, err := pki.NewCSR(cliKey, "client")
		Expect(err).ToNot(HaveOccurred())

		By("Signing the CSR")
		ttl := 5 * 24 * time.Hour
		cliCertPEM, err := pki.SignCSR(srvKey, srvCert, csrPEM, ttl)
		Expect(err).ToNot(HaveOccurred())
		Expect(cliCertPEM).ToNot(BeEmpty())

		blk, _ = pem.Decode([]byte(cliCertPEM))
		Expect(blk).ToNot(BeNil())
		cliCert, err := x509.ParseCertificate(blk.Bytes)
		Expect(err).ToNot(HaveOccurred())
		Expect(cliCert.Subject.CommonName).Should(Equal("client"))
		Expect(cliCert.IsCA).Should(BeFalse(), "client cert should not be CA")
		Expect(cliCert.MaxPathLen).Should(BeZero())
		Expect(cliCert.MaxPathLenZero).Should(BeTrue())
		Expect(cliCert.KeyUsage).Should(Equal(
			x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature))
		Expect(cliCert.ExtKeyUsage).Should(Equal([]x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		}))
		Expect(cliCert.NotBefore).Should(
			BeTemporally("~", time.Now(), time.Second))
		Expect(cliCert.NotAfter).Should(
			BeTemporally("~", time.Now().AddDate(0, 0, 5), time.Second))
	})

	It("can save + load a certificate", func() {
		dir := tmpDir()
		defer rmDir(dir)
		file := filepath.Join(dir, "mycert.pem")

		key, err := pki.GenerateKey()
		Expect(err).ToNot(HaveOccurred())

		certPEM, err := pki.SelfSign(key, "server")
		Expect(err).ToNot(HaveOccurred())

		blk, _ := pem.Decode([]byte(certPEM))
		Expect(blk).ToNot(BeNil())
		Expect(blk.Type).Should(Equal("CERTIFICATE"))

		cert, err := x509.ParseCertificate(blk.Bytes)
		Expect(err).ToNot(HaveOccurred())

		err = pki.SaveCert(certPEM, file)
		Expect(err).ToNot(HaveOccurred())
		Expect(file).Should(BeARegularFile())

		loadedCert, err := pki.LoadCert(file)
		Expect(err).ToNot(HaveOccurred())
		Expect(loadedCert).Should(Equal(cert))
	})
})
