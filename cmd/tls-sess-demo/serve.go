package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	srv "github.com/KibaFox/tls-usr-sessions/grpc"
	"github.com/KibaFox/tls-usr-sessions/pb"
	"github.com/KibaFox/tls-usr-sessions/pki"
)

const serverName = "tls-sess-demo"

func serve(authAddr, protectedAddr, keyPath, caPath string) error {
	anchor, ca, key, err := setupCA(keyPath, caPath)
	if err != nil {
		return err
	}

	tlsCfg, err := setupServerTLS(anchor, keyPath, caPath)
	if err != nil {
		return err
	}

	authCfg := &srv.AuthConfig{
		AnchorsPEM: anchor,
		CA:         ca,
		Key:        key,
		UserTTL:    7 * 24 * time.Hour,
	}

	var eg errgroup.Group
	eg.Go(serveAuth(authAddr, authCfg))
	eg.Go(serveProtected(protectedAddr, tlsCfg))
	return eg.Wait()
}

func serveAuth(addr string, config *srv.AuthConfig) func() error {
	return func() (err error) {
		var lis net.Listener
		lis, err = net.Listen("tcp", addr)
		if err != nil {
			return errors.Wrap(err, "auth server failed to listen")
		}
		log.Println("Auth server listening at:", lis.Addr())

		s := grpc.NewServer()
		pb.RegisterAuthServer(s, srv.NewAuth(config))

		err = s.Serve(lis)
		if err != nil {
			return errors.Wrap(err, "auth server")
		}

		return nil
	}
}

func serveProtected(addr string, tlsCfg *tls.Config) func() error {
	return func() (err error) {
		var lis net.Listener
		lis, err = net.Listen("tcp", addr)
		if err != nil {
			return errors.Wrap(err, "protected server failed to listen")
		}
		log.Println("Protected server listening at:", lis.Addr())

		creds := credentials.NewTLS(tlsCfg)
		s := grpc.NewServer(grpc.Creds(creds))
		pb.RegisterProtectedServer(s, srv.NewProtected())

		err = s.Serve(lis)
		if err != nil {
			return errors.Wrap(err, "protected server")
		}

		return nil
	}
}

func setupCA(keyPath, caPath string) (
	anchor string, ca *x509.Certificate, key *ecdsa.PrivateKey, err error,
) {
	if _, err = os.Stat(keyPath); err != nil {
		log.Println("Key not found. Generating key.")
		key, err = pki.GenerateKey()
		if err != nil {
			return "", nil, nil, err
		}

		log.Println("Saving key to:", keyPath)
		err = os.MkdirAll(filepath.Dir(keyPath), 0777)
		if err != nil {
			return "", nil, nil, err
		}
		err = pki.SaveKey(key, keyPath)
		if err != nil {
			return "", nil, nil, err
		}
	} else {
		log.Println("Loading key from:", keyPath)
		key, err = pki.LoadKey(keyPath)
		if err != nil {
			return "", nil, nil, err
		}
	}

	if _, err = os.Stat(caPath); err != nil {
		log.Println("CA not found.  Self-signing a new CA cert.")
		anchor, err = pki.SelfSign(key, serverName)
		if err != nil {
			return "", nil, nil, err
		}

		log.Println("Saving CA to:", caPath)
		err = os.MkdirAll(filepath.Dir(caPath), 0777)
		if err != nil {
			return "", nil, nil, err
		}
		err = pki.SaveCert(anchor, caPath)
		if err != nil {
			return "", nil, nil, err
		}

		ca, err = pki.PEMtoCert(anchor)
		if err != nil {
			return "", nil, nil, err
		}
	} else {
		log.Println("Loading CA from:", caPath)
		ca, err = pki.LoadCert(caPath)
		if err != nil {
			return "", nil, nil, err
		}
		anchor = string(pki.CertToPEM(ca))
	}

	return anchor, ca, key, nil
}

func setupServerTLS(
	anchor, keyPath, caPath string,
) (tlsCfg *tls.Config, err error) {
	certificate, err := tls.LoadX509KeyPair(caPath, keyPath)
	if err != nil {
		return nil, errors.New("failed to load key pair")
	}

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM([]byte(anchor)); !ok {
		return nil, errors.New("failed to append anchor certs")
	}

	return &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    certPool,
	}, nil
}
