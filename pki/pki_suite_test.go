package pki_test

import (
	"io/ioutil"
	"os"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestPki(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "PKI Suite")
}

func tmpDir() string {
	dir, err := ioutil.TempDir("", "temp")
	Expect(err).ToNot(HaveOccurred())
	err = os.MkdirAll(dir, 0666)
	Expect(err).ToNot(HaveOccurred())
	return dir
}

func rmDir(path string) {
	err := os.RemoveAll(path)
	Expect(err).ToNot(HaveOccurred())
}
