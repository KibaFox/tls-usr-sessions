package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh/terminal"
	"google.golang.org/grpc"

	"github.com/KibaFox/tls-usr-sessions/pb"
	"github.com/KibaFox/tls-usr-sessions/pki"
)

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
