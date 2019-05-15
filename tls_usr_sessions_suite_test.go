package tls_usr_sessions_test

import (
	"bufio"
	"os/exec"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
)

func TestTLSUsrSessions(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "TLS User Sessions Suite")
}

var (
	service *gexec.Session
	addr    string
)

var _ = BeforeSuite(func() {
	service, addr = StartService()
})

var _ = AfterSuite(func() {
	if service != nil {
		service.Kill()
	}
})

func StartService() (session *gexec.Session, addr string) {
	exe, err := gexec.Build(
		"github.com/KibaFox/tls-usr-sessions/cmd/tls-sess-demo")
	Expect(err).ToNot(HaveOccurred(), "problem building service")

	cmd := exec.Command(exe, "serv", "-listen", "127.0.0.1:0")

	session, err = gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).ToNot(HaveOccurred(), "problem starting service")

	Eventually(session.Err, 3).Should(gbytes.Say("Listening at:"),
		"service did not start in time")

	scanner := bufio.NewScanner(session.Err)
	scanner.Split(bufio.ScanWords)
	scanner.Scan()
	Expect(scanner.Err()).ToNot(HaveOccurred(), "couldn't scan for listen addr")
	addr = scanner.Text()
	return session, addr
}
