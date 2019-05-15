package tls_usr_sessions_test

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"

	"github.com/KibaFox/tls-usr-sessions/pb"
)

var _ = Describe("Acceptance", func() {

	It("Should allow login", func() {
		conn, err := grpc.Dial(addr, grpc.WithInsecure())
		Expect(err).ToNot(HaveOccurred(), "could not connect to: %s", addr)
		defer conn.Close()

		cli := pb.NewLoginClient(conn)
		ctx, cancel := context.WithTimeout(
			context.Background(), time.Second)
		defer cancel()

		resp, err := cli.Login(ctx, &pb.LoginRequest{
			Username: "demo",
			Password: "password123",
		})

		Expect(err).ToNot(HaveOccurred(), "problem logging in")

		Expect(resp.Cert).Should(Equal("Got here!"))
	})
})
