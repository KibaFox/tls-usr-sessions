package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
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
		Type:  "EC PRIVATE KEY",
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
	if blk.Type != "EC PRIVATE KEY" {
		return nil, errors.New("file does not contain: EC Private Key")
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
		Type:  "CERTIFICATE REQUEST",
		Bytes: byt,
	}
	return string(pem.EncodeToMemory(blk)), nil
}

func SignCSR(
	key *ecdsa.PrivateKey, parent *x509.Certificate, csrPEM string,
) (certPEM string, err error) {
	blk, _ := pem.Decode([]byte(csrPEM))
	if blk == nil {
		return "", errors.New("could not find PEM")
	}
	if blk.Type != "CERTIFICATE REQUEST" {
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

	tmpl := &x509.Certificate{
		SignatureAlgorithm: csr.SignatureAlgorithm,
		Subject:            csr.Subject,
	}
	byt, err := x509.CreateCertificate(
		rand.Reader, tmpl, parent, csr.PublicKey, key)
	if err != nil {
		return "", errors.Wrap(err, "creating certificate")
	}

	blk = &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: byt,
	}
	return string(pem.EncodeToMemory(blk)), nil
}

// TODO
func SelfSign(key *ecdsa.PrivateKey) (certPEM string, err error) {
	// TODO
	return "", nil
}