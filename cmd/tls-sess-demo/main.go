package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
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
)

const usage = `tls-sess-demo: A demo of using TLS for user sessions

USAGE: tls-sess-demo COMMAND [OPTIONS]

Where COMMAND is one of:

serv    to act as a server
login   to login to a server
motd    to get the message-of-the-day from the server
`

func main() {
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
		err := opts.Parse(os.Args[2:])
		if err != nil {
			log.Fatalf("could not parse options: %v", err)
		}

		var eg errgroup.Group
		eg.Go(serveAuth(*authAddr))
		eg.Go(serveProtected(*protectedAddr))
		if err = eg.Wait(); err == nil {
			log.Fatal(err)
		}
	case "login":
		opts := flag.NewFlagSet(cmd, flag.ExitOnError)
		addr := opts.String("connect", "127.0.0.1:4443",
			"the address to connect to the server")
		err := opts.Parse(os.Args[2:])
		if err != nil {
			log.Fatalf("could not parse options: %v", err)
		}

		err = login(*addr)
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

func serveAuth(addr string) func() error {
	return func() (err error) {
		var lis net.Listener
		lis, err = net.Listen("tcp", addr)
		if err != nil {
			return errors.Wrap(err, "auth server failed to listen")
		}
		log.Println("Auth server listening at:", lis.Addr())

		s := grpc.NewServer()
		pb.RegisterAuthServer(s, srv.NewAuth())

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

func login(addr string) error {
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

	r, err := c.Login(ctx, &pb.LoginRequest{
		Username: usr,
		Password: pass,
		Csr:      "-",
	})

	if err != nil {
		return errors.Wrap(err, "failed to login")
	}

	log.Printf("Response: %v", r)

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
