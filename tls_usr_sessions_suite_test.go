package tls_usr_sessions_test

import (
	"os/exec"
	"regexp"
	"testing"

	"github.com/KibaFox/tls-usr-sessions/pb"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"google.golang.org/grpc"
)

func TestTLSUsrSessions(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "TLS User Sessions Suite")
}

var (
	service *gexec.Session
	auth    string
	addr    string
)

var _ = BeforeSuite(func() {
	service, auth, addr = startService()
})

var _ = AfterSuite(func() {
	if service != nil {
		service.Kill()
	}
})

const listenPattern = `(\w+) server listening at: (.*)`

var listenRx = regexp.MustCompile(listenPattern)

func startService() (session *gexec.Session, auth, addr string) {
	exe, err := gexec.Build(
		"github.com/KibaFox/tls-usr-sessions/cmd/tls-sess-demo")
	Expect(err).ToNot(HaveOccurred(), "problem building service")

	cmd := exec.Command(exe, "serv",
		"-auth", "127.0.0.1:0",
		"-listen", "127.0.0.1:0",
	)

	session, err = gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).ToNot(HaveOccurred(), "problem starting service")

	for i := 1; i <= 2; i++ {
		Eventually(session.Err, 3).Should(gbytes.Say(listenPattern),
			"service did not start in time #%d", i)
	}

	matches := listenRx.FindAllSubmatch(session.Err.Contents(), 2)

	for _, match := range matches {
		Expect(match).Should(HaveLen(3))
		srv, lis := string(match[1]), string(match[2])
		if srv == "Protected" {
			addr = lis
		} else if srv == "Auth" {
			auth = lis
		}
	}

	Expect(auth).ShouldNot(BeEmpty())
	Expect(addr).ShouldNot(BeEmpty())

	return session, auth, addr
}

func authCli() (cli pb.AuthClient, conn *grpc.ClientConn) {
	Expect(auth).ShouldNot(BeEmpty())

	var err error
	conn, err = grpc.Dial(auth, grpc.WithInsecure())
	Expect(err).ToNot(HaveOccurred(), "could not connect to: %s", auth)

	cli = pb.NewAuthClient(conn)

	return cli, conn
}

func protectedCli() (cli pb.ProtectedClient, conn *grpc.ClientConn) {
	Expect(addr).ShouldNot(BeEmpty())

	var err error
	conn, err = grpc.Dial(addr, grpc.WithInsecure())
	Expect(err).ToNot(HaveOccurred(), "could not connect to: %s", addr)

	cli = pb.NewProtectedClient(conn)

	return cli, conn
}
