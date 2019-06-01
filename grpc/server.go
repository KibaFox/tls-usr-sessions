package grpc

import (
	"context"
	"log"

	"github.com/golang/protobuf/ptypes/empty"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/KibaFox/tls-usr-sessions/pb"
)

// Server is used to implement pb.LoginServer
type Server struct{}

// NewServer creates a new gRPC server.
func NewServer() *Server {
	return &Server{}
}

// Login allows a user to start a session.  If the login succeeds, then the
// given CSR is signed and returned as a signed certificate.
func (s *Server) Login(
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

func (s *Server) MOTD(
	ctx context.Context, req *empty.Empty,
) (resp *pb.Bulletin, err error) {
	resp = &pb.Bulletin{
		Bulletin: "Hello and welcome!",
	}

	return resp, nil
}
