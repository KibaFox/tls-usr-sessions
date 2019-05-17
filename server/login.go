package server

import (
	"context"
	"log"

	"github.com/KibaFox/tls-usr-sessions/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// server is used to implement pb.LoginServer
type server struct{}

// NewServer creates a new gRPC server.
func NewServer() *server {
	return &server{}
}

// Login allows a user to start a session.  If the login succeds, then the
// given CSR is signed and returned as a signed certificate.
func (s *server) Login(
	ctx context.Context, req *pb.LoginRequest,
) (resp *pb.LoginResponse, err error) {
	if req.Csr == "" {
		return nil, status.Error(codes.InvalidArgument, "a CSR is required")
	}
	if req.Username == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument,
			"username and password are required")
	}
	log.Printf("Received: %v", req)
	return &pb.LoginResponse{Cert: "Got here!"}, nil
}
