package hysteria2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

type loopTLS struct{ config *tls.Config }

func (c *loopTLS) ServerName() string                   { return c.config.ServerName }
func (c *loopTLS) SetServerName(s string)               { c.config.ServerName = s }
func (c *loopTLS) NextProtos() []string                 { return c.config.NextProtos }
func (c *loopTLS) SetNextProtos(p []string)             { c.config.NextProtos = p }
func (c *loopTLS) HandshakeTimeout() time.Duration      { return 5 * time.Second }
func (c *loopTLS) SetHandshakeTimeout(time.Duration)    {}
func (c *loopTLS) STDConfig() (*tls.Config, error)      { return c.config, nil }
func (c *loopTLS) Client(n net.Conn) (aTLS.Conn, error) { return tls.Client(n, c.config), nil }
func (c *loopTLS) Server(n net.Conn) (aTLS.Conn, error) { return tls.Server(n, c.config), nil }
func (c *loopTLS) Clone() aTLS.Config                   { return &loopTLS{c.config.Clone()} }
func (c *loopTLS) Start() error                         { return nil }
func (c *loopTLS) Close() error                         { return nil }

type loopDialer struct{ sockets atomic.Int32 }

func (d *loopDialer) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	d.sockets.Add(1)
	return (&net.Dialer{}).DialContext(ctx, network, dest.String())
}
func (d *loopDialer) ListenPacket(ctx context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	d.sockets.Add(1)
	return (&net.ListenConfig{}).ListenPacket(ctx, "udp4", "127.0.0.1:0")
}

type echoHandler struct{}

func (echoHandler) NewConnectionEx(_ context.Context, c net.Conn, _, _ M.Socksaddr, closed N.CloseHandlerFunc) {
	go func() {
		_, err := io.Copy(c, c)
		_ = c.Close()
		if closed != nil {
			closed(err)
		}
	}()
}
func (echoHandler) NewPacketConnectionEx(_ context.Context, c N.PacketConn, _, _ M.Socksaddr, closed N.CloseHandlerFunc) {
	_ = c.Close()
	if closed != nil {
		closed(nil)
	}
}

func loopbackServer(t *testing.T) (context.Context, M.Socksaddr, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "routeguard.test"}, DNSNames: []string{"routeguard.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	service, err := NewService[string](ServiceOptions{Context: ctx, Logger: logger.NOP(), TLSConfig: &loopTLS{&tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}}, Handler: echoHandler{}})
	if err != nil {
		t.Fatal(err)
	}
	service.UpdateUsers([]string{"test"}, []string{"test-password"})
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close(); _ = listener.Close() })
	if err = service.Start(listener); err != nil {
		t.Fatal(err)
	}
	return ctx, M.SocksaddrFromNet(listener.LocalAddr()), &tls.Config{RootCAs: roots, ServerName: "routeguard.test", MinVersion: tls.VersionTLS13}
}

func TestWarmAuthenticatedSessionSurvivesIdleAndSharesForegroundDial(t *testing.T) {
	ctx, address, tlsConfig := loopbackServer(t)
	dialer := new(loopDialer)
	client, err := NewClient(ClientOptions{Context: ctx, Dialer: dialer, Logger: logger.NOP(), ServerAddress: address, Password: "test-password", TLSConfig: &loopTLS{tlsConfig}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(errors.New("test ended")) })
	client.SetKeepIdleConnections(true)
	deadline, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	start := make(chan struct{})
	results := make(chan error, 9)
	var pending sync.WaitGroup
	for i := 0; i < 8; i++ {
		pending.Add(1)
		go func() { defer pending.Done(); <-start; results <- client.Warm(deadline) }()
	}
	pending.Add(1)
	go func() {
		defer pending.Done()
		<-start
		conn, err := client.DialConn(deadline, M.ParseSocksaddr("echo.test:443"))
		if err != nil {
			results <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err = conn.Write([]byte("warm")); err == nil {
			buf := make([]byte, 4)
			_, err = io.ReadFull(conn, buf)
			if err == nil && string(buf) != "warm" {
				err = errors.New("echo mismatch")
			}
		}
		results <- err
	}()
	close(start)
	pending.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	snapshot := client.SessionSnapshot()
	if !snapshot.Active || !snapshot.KeepIdle || snapshot.ID != 1 || snapshot.AuthenticatedAtMillis <= 0 || dialer.sockets.Load() != 1 {
		t.Fatalf("unexpected authenticated state: %+v sockets=%d", snapshot, dialer.sockets.Load())
	}
	for i := 0; i < 3; i++ {
		if err = client.Warm(deadline); err != nil {
			t.Fatal(err)
		}
	}
	if client.SessionSnapshot().ID != snapshot.ID || dialer.sockets.Load() != 1 {
		t.Fatal("idle warm requests replaced the authenticated session")
	}
	packet, err := client.ListenPacket(deadline)
	if err != nil {
		t.Fatal(err)
	}
	_ = packet.Close()
	if client.SessionSnapshot().ID != snapshot.ID {
		t.Fatal("UDP session replaced shared transport")
	}
	_ = client.CloseWithError(errors.New("physical epoch revoked"))
	if client.SessionSnapshot().Active {
		t.Fatal("closed transport still reported active")
	}
	if err = client.Warm(deadline); err != nil {
		t.Fatal(err)
	}
	if next := client.SessionSnapshot(); !next.Active || next.ID <= snapshot.ID || dialer.sockets.Load() != 2 {
		t.Fatalf("new authentication did not publish a new session: %+v", next)
	}
}

func TestWarmRejectedAuthenticationNeverReportsActive(t *testing.T) {
	ctx, address, tlsConfig := loopbackServer(t)
	client, err := NewClient(ClientOptions{Context: ctx, Dialer: new(loopDialer), Logger: logger.NOP(), ServerAddress: address, Password: "wrong-password", TLSConfig: &loopTLS{tlsConfig}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(errors.New("test ended")) })
	deadline, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if client.Warm(deadline) == nil {
		t.Fatal("invalid authentication accepted")
	}
	if s := client.SessionSnapshot(); s.Active || s.ID != 0 || s.AuthenticatedAtMillis != 0 {
		t.Fatalf("failed authentication published: %+v", s)
	}
}
