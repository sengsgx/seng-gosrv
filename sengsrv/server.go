package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/pkg/crypto/selfsign"
)

type serverSocket struct {
	udpAddress   *net.UDPAddr
	dtlsConfig   *dtls.Config
	dtlsListener net.Listener
}

func (s *serverSocket) Open() (err error) {
	if s.udpAddress == nil {
		return errors.New("Server Socket address not initialized")
	}
	if s.dtlsConfig == nil {
		return errors.New("Server DTLS Config not initialized")
	}
	s.dtlsListener, err = dtls.Listen("udp", s.udpAddress, s.dtlsConfig)
	return
}

func (s *serverSocket) Close() (err error) {
	if s.udpAddress == nil || s.dtlsConfig == nil {
		return
	}
	err = s.dtlsListener.Close()
	return
}

type serverContext struct {
	ctx    context.Context
	cancel context.CancelFunc
}

type sengServer struct {
	recvTunnel serverSocket
	sendTunnel serverSocket
	srvCert    tls.Certificate
	wg         sync.WaitGroup
	tunIdx     *tunnelIndex
	gwIf       gatewayIf
	srvCtx     *serverContext
}

type serverConfig struct {
	address       string
	dbPath        string
	useNetfltrExt bool
	useShadowing  bool
	certPath      string
	keyPath       string
}

func (s *sengServer) newDtlsSrvConfig() *dtls.Config {
	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{
		Certificates: []tls.Certificate{s.srvCert},

		// TODO: pion dtls does not yet support server RSA keys
		CipherSuites: []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},

		//ExtendedMasterSecret: dtls.RequireExtendedMasterSecret, // runtime doesn't support it

		//ClientAuth: dtls.RequireAndVerifyClientCert,
		ClientAuth:            dtls.RequireAnyClientCert, // will be self-signed
		VerifyPeerCertificate: s.verifyTunnelEnclave,

		// Create timeout context for accepted connection.
		ConnectContextMaker: func() (context.Context, func()) {
			return context.WithTimeout(s.srvCtx.ctx, 30*time.Second)
		},
	}
	return config
}

func (s *sengServer) Init(config serverConfig) (err error) {
	/* Not yet implemented */
	if config.useShadowing {
		fmt.Println("Shadowing not yet supported. Ignored.")
	}
	if config.useNetfltrExt {
		fmt.Println("SENG Netfilter Extension not yet supported. Ignored.")
	}

	/* Load/Generate server ECDSA keys and certificate */
	if config.certPath != "" && config.keyPath != "" {
		s.srvCert, err = tls.LoadX509KeyPair(config.certPath, config.keyPath)
	} else {
		// Generate a certificate and private key to secure the connection
		fmt.Println("Info: using auto-generated, self-signed server certificate")
		s.srvCert, err = selfsign.GenerateSelfSigned() // TODO: seems to create elliptic curve key(s)
	}
	// certificate error
	if err != nil {
		return
	}

	// Create parent context to cleanup handshaking connections on exit.
	s.srvCtx = new(serverContext)
	s.srvCtx.ctx, s.srvCtx.cancel = context.WithCancel(context.Background())

	/* Receive tunnel (#1) */
	s.recvTunnel.udpAddress, err = net.ResolveUDPAddr("udp4", config.address)
	// IPv4-only atm
	if err != nil {
		return
	}
	s.recvTunnel.dtlsConfig = s.newDtlsSrvConfig()

	/* Send tunnel (#2) (warning: no deep copy!) */
	s.sendTunnel.udpAddress = new(net.UDPAddr)
	s.sendTunnel.udpAddress.IP = s.recvTunnel.udpAddress.IP
	s.sendTunnel.udpAddress.Zone = s.recvTunnel.udpAddress.Zone
	s.sendTunnel.udpAddress.Port = s.recvTunnel.udpAddress.Port + 1 // uses `recv-port + 1`
	s.sendTunnel.dtlsConfig = s.newDtlsSrvConfig()

	/* Shared enclave tunnelIndex */
	s.tunIdx = &tunnelIndex{}
	if err = s.tunIdx.Init(config.dbPath); err != nil {
		return
	}

	/* Gateway Forwarder (TUN) */
	s.gwIf = gatewayIf{}
	s.gwIf.Init(s.tunIdx)

	return
}

func (s *sengServer) Open() (err error) {
	/* Create Server's welcome/udp sockets */
	if err = s.recvTunnel.Open(); err != nil {
		return
	}

	if err = s.sendTunnel.Open(); err != nil {
		s.recvTunnel.Close()
		return
	}

	if err = s.gwIf.Open(); err != nil {
		s.recvTunnel.Close()
		s.sendTunnel.Close()
		return
	}

	return
}

func (s *sengServer) Close() (err error) {
	if err = s.sendTunnel.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "Error on closing sendTunnel:", err)
	}

	if err = s.recvTunnel.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "Error on closing recvTunnel:", err)
	}

	if s.srvCtx != nil {
		s.srvCtx.cancel()
		s.srvCtx = nil
	}

	if err = s.gwIf.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "Error on closing gwIf:", err)
	}

	return
}

func (s *sengServer) recvWelcomeLoop() {
	defer s.wg.Done()
	for {
		fmt.Println("Wait for SENG Runtime/SDK connection")
		conn, err := s.recvTunnel.dtlsListener.Accept()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		dtlsConn := conn.(*dtls.Conn) // dtls.Conn
		err = s.setupNewAppTunnel(dtlsConn)
		if err != nil {
			dtlsConn.Close()
			fmt.Fprintln(os.Stderr, "Failed to setup app tunnel:", err)
		}
	}
}

func (s *sengServer) sendWelcomeLoop() {
	defer s.wg.Done()
	for {
		fmt.Println("Wait for paired tunnel connection")
		conn, err := s.sendTunnel.dtlsListener.Accept()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			s.sendTunnel.Close() // TODO
			return
		}
		dtlsConn := conn.(*dtls.Conn) // dtls.Conn

		/* extract SGX quote from client certificate */
		certs := dtlsConn.ConnectionState().PeerCertificates
		leafCert := certs[len(certs)-1]
		var quote *sgxQuote
		if quote, err = extractQuoteFromRawCert(leafCert); err != nil {
			fmt.Fprintln(os.Stderr, "Failed to extract quote from tunnel #2")
			dtlsConn.Close()
			continue
		}

		// check for corresponding appTunnel
		s.tunIdx.tunnelMux.Lock()
		rAddr := dtlsConn.RemoteAddr().(*net.UDPAddr)
		fmt.Println("New #2 connection from:", rAddr)

		infoSet, present := s.tunIdx.GetPendingTunnel(rAddr.IP)
		if !present {
			s.tunIdx.tunnelMux.Unlock()
			fmt.Fprintln(os.Stderr, "#2 connection from unexpected client:", rAddr.String())
			dtlsConn.Close()
			continue
		}

		found := false
		for i, tunInfo := range infoSet {
			if !reflect.DeepEqual(tunInfo.quote, quote) {
				continue
			}
			found = true

			// send handle to #2 tunnel
			err = s.tunIdx.RemovePendingTunnel(rAddr.IP, i)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to remove pending tunnel:", err)
			}
			fmt.Println("Going to send DTLS connection")
			tunInfo.ch <- dtlsConn
			// TODO: could we close the channel here? - close(tunInfo.ch)

			break
		}
		s.tunIdx.tunnelMux.Unlock()
		if !found {
			fmt.Fprintln(os.Stderr, "Failed to find a matching #1 tunnel for the new #2 tunnel")
			dtlsConn.Close()
			continue
		}
	}
}

func (s *sengServer) ServerLoop(wg *sync.WaitGroup) {
	defer wg.Done()

	fmt.Println("Hello from serverLoop")
	s.wg.Add(3)
	go s.sendWelcomeLoop()
	go s.gwIf.RunLoop()
	go s.recvWelcomeLoop()
	s.wg.Wait()
}

func (s *sengServer) setupNewAppTunnel(conn *dtls.Conn) (err error) {
	hostAddr := conn.RemoteAddr().(*net.UDPAddr)
	fmt.Println("New RemoteAddr: ", hostAddr)

	/* extract SGX quote from client certificate */
	certs := conn.ConnectionState().PeerCertificates
	leafCert := certs[len(certs)-1]
	var quote *sgxQuote
	if quote, err = extractQuoteFromRawCert(leafCert); err != nil {
		return
	}

	// get free enclave IP
	var encIP enclaveIP
	if encIP, err = s.tunIdx.SyncAllocIP(quote, hostAddr); err != nil {
		return
	}

	// we still need that one, right?
	gwCh := make(chan []byte, 512)
	s.tunIdx.rwMux.Lock()
	s.tunIdx.encIPtoTunnelC[encIP.String()] = gwCh
	s.tunIdx.rwMux.Unlock()

	appTun := appTunnel{
		uHostAddr:    hostAddr,
		tEnclaveAddr: encIP,
		quote:        quote,

		recvConn: conn,

		toGw:   s.gwIf.Channel(),
		fromGw: gwCh,

		tunIdx: s.tunIdx,
	}
	// spawn goroutine for appTun
	go appTun.OperateAppTunnel()

	return
}
