package main

import (
	"flag"
	"fmt"
	"log"
	"os"
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

		err = serve(*authAddr, *protectedAddr, *keyPath, *caPath)
		if err != nil {
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

		msg, err := motd(*addr, *keyPath, *certPath, *anchorPath)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(msg)

	default:
		fmt.Println(usage)
		os.Exit(0)
	}
}
