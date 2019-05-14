package server

import (
	"context"
	"log"

	"github.com/KibaFox/tls-usr-sessions/pb"
)

// server is used to implement pb.LoginServer
type server struct{}

func NewServer() *server {
	return &server{}
}

// SayHello implements pb.LoginServer
func (s *server) Login(
	ctx context.Context, req *pb.LoginRequest,
) (resp *pb.LoginResponse, err error) {
	log.Printf("Received: %v", req)
	return &pb.LoginResponse{Cert: "Got here!"}, nil
}
