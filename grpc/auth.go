package grpc

import (
	"context"
	"log"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/KibaFox/tls-usr-sessions/pb"
)

// Auth is used to implement pb.AuthServer
type Auth struct{}

// NewAuth creates a new gRPC server.
func NewAuth() *Auth {
	return &Auth{}
}

// Login allows a user to start a session.  If the login succeeds, then the
// given CSR is signed and returned as a signed certificate.
func (s *Auth) Login(
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
