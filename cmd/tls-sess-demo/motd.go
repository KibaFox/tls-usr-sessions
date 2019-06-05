package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/KibaFox/tls-usr-sessions/pb"
)

func motd(addr, keyPath, certPath, anchorPath string) (msg string, err error) {
	tlsCfg, err := setupClientTLS(anchorPath, keyPath, certPath)
	if err != nil {
		return "", err
	}

	creds := credentials.NewTLS(tlsCfg)

	// Set up a connection to the server.
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return "", errors.Wrap(err, "cannot connect")
	}
	defer conn.Close()

	cli := pb.NewProtectedClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := cli.MOTD(ctx, &empty.Empty{})
	if err != nil {
		return "", errors.Wrap(err, "failed to get MOTD")
	}

	return resp.Bulletin, nil
}

func setupClientTLS(
	anchorPath, keyPath, certPath string,
) (tlsCfg *tls.Config, err error) {
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, errors.New("failed to load key pair")
	}

	anchor, err := ioutil.ReadFile(anchorPath)
	if err != nil {
		return nil, errors.Wrap(err, "error reading root anchor file")
	}

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(anchor); !ok {
		return nil, errors.New("failed to append anchor certs")
	}

	return &tls.Config{
		ServerName:   serverName,
		Certificates: []tls.Certificate{certificate},
		RootCAs:      certPool,
	}, nil
}
