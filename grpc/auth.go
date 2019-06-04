package grpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"log"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/KibaFox/tls-usr-sessions/pb"
	"github.com/KibaFox/tls-usr-sessions/pki"
)

// Static username and password for demonstration.
const (
	username = "demo"
	password = "test123" // in prod, store passwords with a password hash + salt
)

type AuthConfig struct {
	AnchorsPEM string
	CA         *x509.Certificate
	Key        *ecdsa.PrivateKey
	UserTTL    time.Duration
}

// Auth is used to implement pb.AuthServer
type Auth struct {
	Config *AuthConfig
}

// NewAuth creates a new gRPC server.
func NewAuth(config *AuthConfig) *Auth {
	return &Auth{Config: config}
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

	if req.Username != username || req.Password != password {
		return nil, status.Error(codes.InvalidArgument,
			"incorrect username or password")
	}

	cert, err := pki.SignCSR(
		s.Config.Key, s.Config.CA, req.Csr, s.Config.UserTTL)
	if err != nil {
		return nil, err
	}

	return &pb.LoginResponse{Cert: cert, Anchors: s.Config.AnchorsPEM}, nil
}
