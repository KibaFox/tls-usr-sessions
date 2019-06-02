package grpc

import (
	"context"
	"log"

	"github.com/golang/protobuf/ptypes/empty"

	"github.com/KibaFox/tls-usr-sessions/pb"
)

// Protected is used to implement pb.ProtectedServer
type Protected struct{}

// NewProtected creates a new gRPC server.
func NewProtected() *Protected {
	return &Protected{}
}

// MOTD will return a message-of-the-day bulletin.
func (s *Protected) MOTD(
	ctx context.Context, req *empty.Empty,
) (resp *pb.Bulletin, err error) {
	resp = &pb.Bulletin{
		Bulletin: "Hello and welcome!",
	}
	log.Println("Received: request for MOTD")
	return resp, nil
}
