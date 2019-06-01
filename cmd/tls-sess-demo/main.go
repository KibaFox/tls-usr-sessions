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

	"golang.org/x/crypto/ssh/terminal"
	"google.golang.org/grpc"

	srv "github.com/KibaFox/tls-usr-sessions/grpc"
	"github.com/KibaFox/tls-usr-sessions/pb"
)

const usage = `tls-sess-demo: A demo of using TLS for user sessions

USAGE: tls-sess-demo COMMAND [OPTIONS]

Where COMMAND is one of:

serv    to act as a server
login   to login to a server
`

func main() {
	var cmd string
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	switch cmd {
	case "serv":
		opts := flag.NewFlagSet(cmd, flag.ExitOnError)
		addr := opts.String("listen", "127.0.0.1:4443",
			"the address to listen on")
		err := opts.Parse(os.Args[2:])
		if err != nil {
			log.Fatalf("could not parse options: %v", err)
		}
		lis, err := net.Listen("tcp", *addr)
		if err != nil {
			log.Fatalf("failed to listen: %v", err)
		}
		log.Println("Listening at:", lis.Addr())
		s := grpc.NewServer()
		pb.RegisterDemoServer(s, srv.NewServer())
		if err := s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	case "login":
		opts := flag.NewFlagSet(cmd, flag.ExitOnError)
		addr := opts.String("connect", "127.0.0.1:4443",
			"the address to connect to the server")
		err := opts.Parse(os.Args[2:])
		if err != nil {
			log.Fatalf("could not parse options: %v", err)
		}
		usr, pass := credentials()

		// Set up a connection to the server.
		conn, err := grpc.Dial(*addr, grpc.WithInsecure())
		if err != nil {
			log.Fatalf("did not connect: %v", err)
		}
		defer conn.Close()
		c := pb.NewDemoClient(conn)
		ctx, cancel := context.WithTimeout(
			context.Background(), time.Second)
		defer cancel()
		r, err := c.Login(ctx, &pb.LoginRequest{
			Username: usr,
			Password: pass,
		})
		if err != nil {
			log.Fatalf("could not greet: %v", err)
		}
		log.Printf("Response: %v", r)

	default:
		fmt.Println(usage)
		os.Exit(0)
	}
}

// origin: https://stackoverflow.com/a/32768479
func credentials() (string, string) {
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
