package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"

	srv "github.com/KibaFox/tls-usr-sessions/grpc"
	"github.com/KibaFox/tls-usr-sessions/pb"
	"github.com/KibaFox/tls-usr-sessions/pki"
)

const usage = `tls-sess-demo: A demo of using TLS for user sessions

USAGE: tls-sess-demo COMMAND [OPTIONS]

Where COMMAND is one of:

serv    to act as a server
login   to login to a server
motd    to get the message-of-the-day from the server
`

func main() { // nolint: gocyclo
	var cmd string
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	switch cmd {
	case "serv":
		opts := flag.NewFlagSet(cmd, flag.ExitOnError)
		authAddr := opts.String("auth", "127.0.0.1:4443",
			"the address to listen on for login requests")
		protectedAddr := opts.String("listen", "127.0.0.1:4444",
			"the address to listen on for protected requests")
		keyPath := opts.String("key", "certs/ca_key.pem",
			"path to the CA key file in PEM format")
		caPath := opts.String("ca", "certs/ca_cert.pem",
			"path to the CA certificate file in PEM format")
		err := opts.Parse(os.Args[2:])
		if err != nil {
			log.Fatalf("could not parse options: %v", err)
		}

		anchor, ca, key, err := setupCA(*keyPath, *caPath)
		if err != nil {
			log.Fatal(err)
		}

		authCfg := &srv.AuthConfig{
			AnchorsPEM: anchor,
			CA:         ca,
			Key:        key,
			UserTTL:    7 * 24 * time.Hour,
		}

		var eg errgroup.Group
		eg.Go(serveAuth(*authAddr, authCfg))
		eg.Go(serveProtected(*protectedAddr))
		if err = eg.Wait(); err == nil {
			log.Fatal(err)
		}
	case "login":
		opts := flag.NewFlagSet(cmd, flag.ExitOnError)
		addr := opts.String("connect", "127.0.0.1:4443",
			"the address to connect to the server")
		keyPath := opts.String("key", "certs/cli_key.pem",
			"path to the client key file in PEM format")
		certPath := opts.String("cert", "certs/cli_cert.pem",
			"path to the client certificate file in PEM format")
		anchorPath := opts.String("root", "certs/root.pem",
			"path to the root anchor certificate file in PEM format")
		err := opts.Parse(os.Args[2:])
		if err != nil {
			log.Fatalf("could not parse options: %v", err)
		}

		err = login(*addr, *keyPath, *certPath, *anchorPath)
		if err != nil {
			log.Fatal(err)
		}

	case "motd":
		opts := flag.NewFlagSet(cmd, flag.ExitOnError)
		addr := opts.String("connect", "127.0.0.1:4444",
			"the address to connect to the server")
		err := opts.Parse(os.Args[2:])
		if err != nil {
			log.Fatalf("could not parse options: %v", err)
		}

		msg, err := motd(*addr)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(msg)

	default:
		fmt.Println(usage)
		os.Exit(0)
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
		anchor, err = pki.SelfSign(key, "tls-sess-demo")
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

// origin: https://stackoverflow.com/a/32768479
func userCredentials() (string, string) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter Username: ")
	username, _ := reader.ReadString('\n')

	fmt.Print("Enter Password: ")
	bytePassword, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		log.Fatalf("could not read password: %v", err)
	}
	password := string(bytePassword)

	return strings.TrimSpace(username), strings.TrimSpace(password)
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

func serveProtected(addr string) func() error {
	return func() (err error) {
		var lis net.Listener
		lis, err = net.Listen("tcp", addr)
		if err != nil {
			return errors.Wrap(err, "protected server failed to listen")
		}
		log.Println("Protected server listening at:", lis.Addr())

		/*
			creds, _ := credentials.NewServerTLSFromFile(certFile, keyFile)
			s := grpc.NewServer(grpc.Creds(creds))
		*/
		s := grpc.NewServer()
		pb.RegisterProtectedServer(s, srv.NewProtected())

		err = s.Serve(lis)
		if err != nil {
			return errors.Wrap(err, "protected server")
		}

		return nil
	}
}

func login(addr, keyPath, certPath, anchorPath string) (err error) {
	var key *ecdsa.PrivateKey
	if _, err = os.Stat(keyPath); err != nil {
		key, err = pki.GenerateKey()
		if err != nil {
			return err
		}

		err = os.MkdirAll(filepath.Dir(keyPath), 0777)
		if err != nil {
			return errors.Wrap(err, "creating directory for key")
		}
		err = pki.SaveKey(key, keyPath)
		if err != nil {
			return err
		}
	} else {
		key, err = pki.LoadKey(keyPath)
		if err != nil {
			return err
		}
	}
	csr, err := pki.NewCSR(key, "client")
	if err != nil {
		return err
	}

	usr, pass := userCredentials()

	// Set up a connection to the server.
	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		return errors.Wrap(err, "cannot connect")
	}
	defer conn.Close()

	c := pb.NewAuthClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.Login(ctx, &pb.LoginRequest{
		Username: usr,
		Password: pass,
		Csr:      csr,
	})

	if err != nil {
		return errors.Wrap(err, "failed to login")
	}

	err = pki.SaveCert(resp.Cert, certPath)
	if err != nil {
		return errors.Wrap(err, "error saving client cert")
	}

	err = pki.SaveCert(resp.Anchors, anchorPath)
	if err != nil {
		return errors.Wrap(err, "error saving anchor cert")
	}

	return nil
}

func motd(addr string) (msg string, err error) {
	// Set up a connection to the server.
	conn, err := grpc.Dial(addr, grpc.WithInsecure())
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
