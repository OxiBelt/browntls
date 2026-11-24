// Command pion-dtls drives one mutually authenticated DTLS association through
// a UDP source port change. The client and server exchange distinct datagrams
// on each path, using the same application protocol as browntls-e2e.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/pion/dtls/v4"
	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4/pkg/protocol"
)

const (
	initial = "hello from browntls"
	rebound = "hello after rebind"
)

func reverse(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

func expect(c *dtls.Conn, want string) error {
	var buf [1200]byte
	n, err := c.Read(buf[:])
	if err != nil {
		return err
	}
	if string(buf[:n]) != want {
		return fmt.Errorf("unexpected datagram while waiting for %q", want)
	}
	return nil
}

func send(c *dtls.Conn, s string) error {
	n, err := c.Write([]byte(s))
	if err == nil && n != len(s) {
		return io.ErrShortWrite
	}
	return err
}

func authenticate(ctx context.Context, c *dtls.Conn, version protocol.Version) error {
	deadline, _ := ctx.Deadline()
	if err := c.SetDeadline(deadline); err != nil {
		return err
	}
	if err := c.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	state, ok := c.ConnectionState()
	if !ok || state.NegotiatedVersion() != version || len(state.PeerCertificates) == 0 {
		return errors.New("missing negotiated version or authenticated peer certificate")
	}
	return nil
}

type paths struct {
	Before string `json:"before"`
	After  string `json:"after"`
}

func serve(ctx context.Context, addr *net.UDPAddr, version protocol.Version, opts []dtls.ServerOption) (paths, error) {
	listener, err := dtls.ListenAddr("udp4", addr, opts...)
	if err != nil {
		return paths{}, err
	}
	defer listener.Close()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	fmt.Println("listening")
	accepted, err := listener.Accept()
	if err != nil {
		return paths{}, err
	}
	c := accepted.(*dtls.Conn)
	defer c.Close()
	if err := authenticate(ctx, c, version); err != nil {
		return paths{}, err
	}
	before := c.RemoteAddr().String()
	if err := expect(c, initial); err != nil {
		return paths{}, err
	}
	if err := send(c, reverse(initial)); err != nil {
		return paths{}, err
	}
	for {
		if err := expect(c, rebound); err != nil {
			return paths{}, err
		}
		// RRC is the only configured policy that can change RemoteAddr.
		// Send the reply only after Pion adopts the new peer address.
		after := c.RemoteAddr().String()
		if after != before {
			if err := send(c, reverse(rebound)); err != nil {
				return paths{}, err
			}
			return paths{before, after}, c.Close()
		}
	}
}

func migrate(ctx context.Context, addr *net.UDPAddr, version protocol.Version, opts []dtls.ClientOption) (paths, error) {
	first, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return paths{}, err
	}
	defer first.Close()
	c, err := dtls.Client(first, addr, opts...)
	if err != nil {
		return paths{}, err
	}
	defer c.Close()
	if err := authenticate(ctx, c, version); err != nil {
		return paths{}, err
	}
	before := c.LocalAddr().String()
	if err := send(c, initial); err != nil {
		return paths{}, err
	}
	if err := expect(c, reverse(initial)); err != nil {
		return paths{}, err
	}
	second, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return paths{}, err
	}
	path, err := c.AddPath(second)
	if err != nil {
		second.Close()
		return paths{}, fmt.Errorf("AddPath: %w", err)
	}
	if err := path.Probe(ctx); err != nil {
		return paths{}, fmt.Errorf("Probe: %w", err)
	}
	if err := path.Switch(); err != nil {
		return paths{}, fmt.Errorf("Switch: %w", err)
	}
	after := c.LocalAddr().String()
	if before == after || second.LocalAddr().String() != after {
		return paths{}, errors.New("Switch did not select the replacement socket")
	}
	// The enhanced validator can now observe that the old path is gone.
	if err := first.Close(); err != nil {
		return paths{}, err
	}
	deadline, _ := ctx.Deadline()
	for ctx.Err() == nil {
		if err := send(c, rebound); err != nil {
			return paths{}, err
		}
		wake := time.Now().Add(250 * time.Millisecond)
		if wake.After(deadline) {
			wake = deadline
		}
		if err := c.SetReadDeadline(wake); err != nil {
			return paths{}, err
		}
		err := expect(c, reverse(rebound))
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			continue
		}
		if err != nil {
			return paths{}, err
		}
		if err := c.SetReadDeadline(deadline); err != nil {
			return paths{}, err
		}
		var buf [1200]byte
		if _, err := c.Read(buf[:]); !errors.Is(err, io.EOF) {
			return paths{}, fmt.Errorf("expected peer close, got %v", err)
		}
		return paths{before, after}, nil
	}
	return paths{}, ctx.Err()
}

func run(args []string) error {
	if len(args) != 4 {
		return errors.New("usage: pion-dtls server|client server-name port 1.2|1.3")
	}
	role, host, port, v := args[0], args[1], args[2], args[3]
	version := protocol.Version1_3
	if v == "1.2" && role == "server" {
		version = protocol.Version1_2
	} else if v != "1.3" {
		return errors.New("Pion initiates local migration only on DTLS 1.3")
	}
	if role != "client" && role != "server" {
		return errors.New("unknown role")
	}
	dir := "/pki/ecdsa-p256"
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, role+".pem"), filepath.Join(dir, role+".key"))
	if err != nil {
		return err
	}
	pem, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return errors.New("invalid test CA")
	}
	opts := []dtls.Option{
		dtls.WithMinVersion(version), dtls.WithMaxVersion(version),
		dtls.WithConnectionID(dtls.RandomCIDGenerator(8), dtls.CIDPathMigrationRRC),
		dtls.WithCertificates(cert), dtls.WithEllipticCurves(elliptic.P256),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	var observed paths
	if role == "server" {
		addr, err := net.ResolveUDPAddr("udp4", ":"+port)
		if err != nil {
			return err
		}
		server := []dtls.ServerOption{dtls.WithClientAuth(dtls.RequireAndVerifyClientCert), dtls.WithClientCAs(roots)}
		for _, opt := range opts {
			server = append(server, opt)
		}
		observed, err = serve(ctx, addr, version, server)
		if err != nil {
			return err
		}
	} else {
		addr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(host, port))
		if err != nil {
			return err
		}
		client := []dtls.ClientOption{dtls.WithRootCAs(roots), dtls.WithServerName(host)}
		for _, opt := range opts {
			client = append(client, opt)
		}
		observed, err = migrate(ctx, addr, version, client)
		if err != nil {
			return err
		}
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Event   string `json:"event"`
		Role    string `json:"role"`
		Version string `json:"version"`
		paths
	}{"migration", role, v, observed})
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
