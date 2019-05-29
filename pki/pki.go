package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"

	"github.com/pkg/errors"
)

const (
	keyPEMtype  = "EC PRIVATE KEY"
	csrPEMtype  = "CERTIFICATE REQUEST"
	certPEMtype = "CERTIFICATE"
)

// GenerateKey will generate a new ECDSA private key.
func GenerateKey() (key *ecdsa.PrivateKey, err error) {
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "generating key")
	}

	return key, nil
}

// SaveKey saves an ECDSA private key to a file in PEM format.
func SaveKey(key *ecdsa.PrivateKey, path string) (err error) {
	byt, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return errors.Wrap(err, "marshalling key to save")
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return errors.Wrap(err, "opening file to save key")
	}
	defer f.Close()

	blk := &pem.Block{
		Type:  keyPEMtype,
		Bytes: byt,
	}

	err = pem.Encode(f, blk)
	if err != nil {
		return errors.Wrap(err, "encoding key to PEM while saving")
	}

	return nil
}

// LoadKey will load an ECDSA private key file that's encoded in PEM format.
// Encrypted key files are not supported.
func LoadKey(path string) (key *ecdsa.PrivateKey, err error) {
	byt, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.Wrap(err, "reading the key file")
	}

	blk, _ := pem.Decode(byt)
	if blk == nil {
		return nil, errors.New("could not find PEM")
	}
	if blk.Type != keyPEMtype {
		return nil, fmt.Errorf("PEM is not of type: %s", keyPEMtype)
	}

	key, err = x509.ParseECPrivateKey(blk.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "parsing EC private key")
	}

	return key, nil
}

// NewCSR creates a new certificate signing request (CSR) from the given private
// key and the common name (CN) and returns the CSR in PEM format.
func NewCSR(key *ecdsa.PrivateKey, cn string) (csrPEM string, err error) {
	tmpl := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Subject: pkix.Name{
			CommonName: cn,
		},
	}

	byt, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return "", errors.Wrap(err, "creating CSR")
	}

	blk := &pem.Block{
		Type:  csrPEMtype,
		Bytes: byt,
	}
	return string(pem.EncodeToMemory(blk)), nil
}

func SignCSR(
	key *ecdsa.PrivateKey,
	parent *x509.Certificate,
	csrPEM string,
	ttl time.Duration,
) (certPEM string, err error) {
	blk, _ := pem.Decode([]byte(csrPEM))
	if blk == nil {
		return "", errors.New("could not find PEM")
	}
	if blk.Type != csrPEMtype {
		return "", errors.New("PEM is not a certificate request")
	}

	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return "", errors.Wrap(err, "parsing certificate request")
	}

	err = csr.CheckSignature()
	if err != nil {
		return "", errors.Wrap(err, "checking CSR signature")
	}

	serialNumber, err := newSerial()
	if err != nil {
		return "", errors.Wrap(err, "generating serial number")
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serialNumber,
		SignatureAlgorithm:    csr.SignatureAlgorithm,
		Subject:               csr.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(ttl),
		IsCA:                  false,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature,
	}
	byt, err := x509.CreateCertificate(
		rand.Reader, tmpl, parent, csr.PublicKey, key)
	if err != nil {
		return "", errors.Wrap(err, "creating certificate")
	}

	blk = &pem.Block{
		Type:  certPEMtype,
		Bytes: byt,
	}
	return string(pem.EncodeToMemory(blk)), nil
}

// SelfSign will create a new self signed CA certificate with the given key and
// common name (CN).
func SelfSign(key *ecdsa.PrivateKey, cn string) (certPEM string, err error) {
	// Template and serial number inspired from:
	// https://golang.org/src/crypto/tls/generate_cert.go
	serialNumber, err := newSerial()
	if err != nil {
		return "", errors.Wrap(err, "generating serial number")
	}

	tmpl := x509.Certificate{
		SerialNumber:       serialNumber,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(5, 0, 0), // years
		IsCA:           true,
		MaxPathLen:     0,
		MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	byt, err := x509.CreateCertificate(
		rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return "", errors.Wrap(err, "creating self-signed certificate")
	}

	blk := &pem.Block{
		Type:  certPEMtype,
		Bytes: byt,
	}
	return string(pem.EncodeToMemory(blk)), nil
}

// SaveCert saves a certificate in PEM format to a file.
func SaveCert(certPEM string, path string) (err error) {
	err = ioutil.WriteFile(path, []byte(certPEM), 0666)
	if err != nil {
		return errors.Wrap(err, "saving certificate")
	}
	return nil
}

func LoadCert(path string) (cert *x509.Certificate, err error) {
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.Wrap(err, "reading certificate file")
	}

	blk, _ := pem.Decode(raw)
	if blk == nil {
		return nil, errors.New("could not find PEM")
	}
	if blk.Type != certPEMtype {
		return nil, fmt.Errorf("PEM is not of type: %s", certPEMtype)
	}

	cert, err = x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "parsing x509 certificate")
	}

	return cert, nil
}

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

func newSerial() (serial *big.Int, err error) {
	return rand.Int(rand.Reader, serialNumberLimit)
}
