# User Sessions w/ TLS Mutual Auth

This project is a proof-of-concept that demonstrates a method of handling a user
session once a user is authenticated using TLS mutual authentication with x509
certificates; while maintaining a user friendly experience on the client.  This
is an alternative to traditonal session management built on top of the HTTP
that typically involve session tokens inserted into headers or provided via
cookies.

The user is presented with a familiar login workflow by providing a username and
password when initiating a new session.  Behind the scenes, the client sends a
certificate signing request (CSR) along with the username and password, and the
server issues a signed certificate on a successful login.  The client then uses
its issued signed certificate via TLS mutual authentication for the user
session.

A user can start a session on more than one device.  Each time a new device is
used with the server, the user must authenticate with a username and password to
get a signed certificate for their device.

The server generates a self-signed certificate certificate for itself to become
a certificate authority (CA) for authenticated user sessions.  The client must
include this certificate into its trusted chain upon login.

![sequence diagram](./doc/sequence.svg)

Note that this is a demonstration and not intended for production use.  For
example, the login method is a placeholder for implementing your own.  You will
want to store the password as a password hash such as argon2, scrypt, or bcrypt
with a salt.  In addition, you can also use some other vector to verify the
user, such as 2FA and/or email validation.  The login endpoint should also be
protected with TLS using server verification.  You can accomplish this for free
with certificates from [Let's Encrypt](https://letsencrypt.org/).

Also, you will want to do your own audit of certificate use if you decide to
implement this in your own project.  This demo uses a single key type for
simplicity and does not address revocation via CRL or OCSP.

### Advantages

The advantage of using TLS mutual auth for the user session is similar to using
token authentication. You can store entitlement information into the certificate
you sign and give to the client.  For example, you can put information in the
subject that identifies the client as an admin and since the certificate is
signed by the server upon login, you can trust the client certificate without
doing a database lookup that is usual for cookie-based authentication.

TLS does not depend on HTTP which means you can use this method for more than
protecting an HTTP API.  For example, you can use the certifiate to authenticate
a user to a VPN such as IPsec/IKEv2 or OpenVPN.

### Disadvantages

While browsers support TLS mutual auth, they depend on the operating system's
certificate manager.  You are likely to be limited in making the experience easy
on the user as you may have to get the user to add the trusted CA certificate
and the client certificate into the operating system's certificate manager.

It appears that a separate port is needed for login that's configured without
TLS mutual auth.  There doesn't appear to be a way to require mutual auth for
come endpoints and not for others on the same port.  Opening multiple ports for
this is unsual for a normal HTTP/S service and may throw a red flag with
a security team.

## Generating Protobuf

Make sure you have `protoc` and `protoc-gen-go` installed.

Follow instructions here: https://developers.google.com/protocol-buffers/docs/gotutorial#compiling-your-protocol-buffers

To generate the Go protobuf code, run:

    protoc -I=pb --go_out=plugins=grpc:pb auth.proto
    protoc -I=pb --go_out=plugins=grpc:pb protected.proto

## Making the Demo

You must have [Go](https://golang.org) installed to compile the demo.

A `Makefile` is provided for convenience.  You can see what targets are
available by simply running:

    make

To compile the demo, run the following:

    make build

If you do not have GNU Make, you can run:

    go build -o ./dist/tls-sess-demo ./cmd/tls-sess-demo

## Running the Demo

After compiling the demo, you can run it via:

    ./dist/tls-sess-demo

This will print out the commands available.

To run the demo, you'll need two terminal sessions.  On one, start up the server
by running:

    ./dist/tls-sess-demo serv

In the other terminal, login to the server via:

    ./dist/tls-sess-demo login
    Enter Username: demo
    Enter Password: test123

The username is `demo` and the password is `test123`.  Note that the password
prompt will not display your password as you type.

Enter some phony credentials.

Then run the following to get the server's message-of-the-day:

    ./dist/tls-sess-demo motd

By default, the certificates used will be stored in the `./certs` folder.

## Testing

This project uses [Ginkgo](https://github.com/onsi/ginkgo) for testing.  To
install, run:

    go get -u github.com/onsi/ginkgo/ginkgo

To run the tests, run:

    make test

## Linting

This project uses [golangci-lint](https://github.com/golangci/golangci-lint) for
linting which performs static code analysis checks.  To install, run:

    GO111MODULE=on go get github.com/golangci/golangci-lint/cmd/golangci-lint@v1.16.0

To run linters, run:

    make lint
