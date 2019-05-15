package tls_usr_sessions_test

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/KibaFox/tls-usr-sessions/pb"
)

var _ = Describe("Acceptance", func() {

	It("Requires a CSR at login", func() {
		conn, err := grpc.Dial(addr, grpc.WithInsecure())
		Expect(err).ToNot(HaveOccurred(), "could not connect to: %s", addr)
		defer conn.Close()

		cli := pb.NewLoginClient(conn)
		ctx, cancel := context.WithTimeout(
			context.Background(), time.Second)
		defer cancel()

		By("Requesting login without a CSR")
		_, err = cli.Login(ctx, &pb.LoginRequest{
			Username: "demo",
			Password: "password123",
		})

		Expect(err).To(HaveOccurred(), "server accepted the login request")
		Expect(status.Code(err)).Should(Equal(codes.InvalidArgument))
		s := status.Convert(err)
		Expect(s.Message()).Should(Equal("a CSR is required"))
	})

	It("Should require username and password", func() {
		conn, err := grpc.Dial(addr, grpc.WithInsecure())
		Expect(err).ToNot(HaveOccurred(), "could not connect to: %s", addr)
		defer conn.Close()

		cli := pb.NewLoginClient(conn)
		ctx, cancel := context.WithTimeout(
			context.Background(), time.Second)
		defer cancel()

		By("Requesting login without a CSR")
		_, err = cli.Login(ctx, &pb.LoginRequest{
			Csr: "-",
		})

		Expect(err).To(HaveOccurred(), "server accepted the login request")
		Expect(status.Code(err)).Should(Equal(codes.InvalidArgument))
		s := status.Convert(err)
		Expect(s.Message()).Should(Equal("username and password are required"))
	})

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
			Csr:      "-",
		})

		Expect(err).ToNot(HaveOccurred(), "problem logging in")

		Expect(resp.Cert).Should(Equal("Got here!"))
	})
})
