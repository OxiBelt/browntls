// Command go-peer is the Go crypto/tls peer of the browntls Docker
// end-to-end matrix (tests/e2e/): an Encrypted Client Hello (RFC 9849)
// client and shared-mode server.
//
//	go-peer server -listen ADDR -cert FILE -key FILE [-cert FILE -key FILE]
//	               -ech-config FILE -ech-key FILE [-accept N] [-p256-only]
//	go-peer client -connect HOST:PORT -server-name NAME -ca FILE
//	               -ech-config-list FILE [-message TEXT] [-retry]
//
// The server answers the first line of each connection with the line
// reversed and closes the connection; the client sends one line and prints
// the reply. Results are written to standard output as one JSON object per
// line, like the browntls-e2e peer: "listening", "connection" (with
// "ech_accepted"), "ech-rejected" and "error". The exit status is non-zero
// after any error.
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func emit(fields map[string]any) {
	line, _ := json.Marshal(fields)
	fmt.Println(string(line))
}

func fail(err error) {
	emit(map[string]any{"event": "error", "message": err.Error()})
	os.Exit(1)
}

func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLSv1_3"
	case tls.VersionTLS12:
		return "TLSv1_2"
	}
	return fmt.Sprintf("0x%04x", v)
}

func main() {
	if len(os.Args) < 2 {
		fail(errors.New("usage: go-peer server|client [flags]"))
	}
	switch os.Args[1] {
	case "server":
		server(os.Args[2:])
	case "client":
		client(os.Args[2:])
	default:
		fail(fmt.Errorf("unknown command %q", os.Args[1]))
	}
}

func server(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	listen := fs.String("listen", ":4433", "address to listen on")
	var certs, keys multi
	fs.Var(&certs, "cert", "certificate chain (PEM), repeatable")
	fs.Var(&keys, "key", "private key (PEM), one per -cert")
	echConfig := fs.String("ech-config", "", "ECHConfig (binary)")
	echKey := fs.String("ech-key", "", "ECH private key (raw)")
	accept := fs.Int("accept", 1, "connections to serve")
	p256Only := fs.Bool("p256-only", false, "accept only P-256 key shares")
	_ = fs.Parse(args)

	config := &tls.Config{MinVersion: tls.VersionTLS13}
	if len(certs) != len(keys) || len(certs) == 0 {
		fail(errors.New("-cert and -key go together"))
	}
	for i := range certs {
		pair, err := tls.LoadX509KeyPair(certs[i], keys[i])
		if err != nil {
			fail(err)
		}
		config.Certificates = append(config.Certificates, pair)
	}
	if *echConfig != "" {
		cfg, err := os.ReadFile(*echConfig)
		if err != nil {
			fail(err)
		}
		key, err := os.ReadFile(*echKey)
		if err != nil {
			fail(err)
		}
		config.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{
			{Config: cfg, PrivateKey: key, SendAsRetry: true},
		}
	}
	if *p256Only {
		config.CurvePreferences = []tls.CurveID{tls.CurveP256}
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fail(err)
	}
	emit(map[string]any{"event": "listening", "addr": ln.Addr().String()})
	failed := false
	for i := 0; i < *accept; i++ {
		conn, err := ln.Accept()
		if err != nil {
			fail(err)
		}
		if err := serve(tls.Server(conn, config), i); err != nil {
			// A client that rejected ECH ends with ech_required (RFC 9849
			// §6.1.6): expected when it retries.
			if strings.Contains(err.Error(), "encrypted client hello") ||
				strings.Contains(err.Error(), "ech required") {
				emit(map[string]any{"event": "ech-required", "index": i, "message": err.Error()})
				continue
			}
			emit(map[string]any{"event": "error", "index": i, "message": err.Error()})
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
}

func serve(conn *tls.Conn, index int) error {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := conn.Handshake(); err != nil {
		return err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return err
	}
	line = strings.TrimRight(line, "\r\n")
	runes := []rune(line)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	reply := string(runes)
	if _, err := conn.Write([]byte(reply + "\n")); err != nil {
		return err
	}
	state := conn.ConnectionState()
	emit(map[string]any{
		"event":        "connection",
		"role":         "server",
		"index":        index,
		"version":      versionName(state.Version),
		"server_name":  state.ServerName,
		"ech_accepted": state.ECHAccepted,
		"handshake":    handshakeKind(state),
		"received":     line,
		"sent":         reply,
	})
	return conn.CloseWrite()
}

func handshakeKind(state tls.ConnectionState) string {
	if state.DidResume {
		return "Resumed"
	}
	if state.HelloRetryRequest {
		return "FullWithHelloRetryRequest"
	}
	return "Full"
}

func client(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	connect := fs.String("connect", "", "HOST:PORT")
	serverName := fs.String("server-name", "", "server name")
	ca := fs.String("ca", "", "trusted CA (PEM)")
	echList := fs.String("ech-config-list", "", "ECHConfigList (binary)")
	message := fs.String("message", "hello from go", "line to send")
	retry := fs.Bool("retry", false, "retry once with the retry configurations")
	wait := fs.Int("wait", 30, "seconds to wait for the server")
	_ = fs.Parse(args)

	pem, err := os.ReadFile(*ca)
	if err != nil {
		fail(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		fail(errors.New("no CA certificate"))
	}
	list, err := os.ReadFile(*echList)
	if err != nil {
		fail(err)
	}
	for attempt := 0; ; attempt++ {
		config := &tls.Config{
			MinVersion:                     tls.VersionTLS13,
			ServerName:                     *serverName,
			RootCAs:                        roots,
			EncryptedClientHelloConfigList: list,
		}
		err := exchange(*connect, config, *message, time.Duration(*wait)*time.Second)
		var rejected *tls.ECHRejectionError
		if errors.As(err, &rejected) {
			emit(map[string]any{
				"event":         "ech-rejected",
				"retry_configs": len(rejected.RetryConfigList) > 0,
			})
			if *retry && attempt == 0 && len(rejected.RetryConfigList) > 0 {
				list = rejected.RetryConfigList
				continue
			}
		}
		if err != nil {
			fail(err)
		}
		return
	}
}

func exchange(addr string, config *tls.Config, message string, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	var raw net.Conn
	var err error
	for {
		raw, err = net.DialTimeout("tcp", addr, 5*time.Second)
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	conn := tls.Client(raw, config)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := conn.Handshake(); err != nil {
		return err
	}
	if _, err := conn.Write([]byte(message + "\n")); err != nil {
		return err
	}
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return err
	}
	reply = strings.TrimRight(reply, "\r\n")
	state := conn.ConnectionState()
	emit(map[string]any{
		"event":        "connection",
		"role":         "client",
		"index":        0,
		"version":      versionName(state.Version),
		"ech_accepted": state.ECHAccepted,
		"handshake":    handshakeKind(state),
		"sent":         message,
		"received":     reply,
	})
	return nil
}
