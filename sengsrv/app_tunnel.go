package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/ipv4"

	proto "github.com/golang/protobuf/proto"
	seng_proto "github.com/sengsgx/seng-gosrv/seng-proto"

	"github.com/pion/dtls/v2"
)

type appTunnel struct {
	uHostAddr    *net.UDPAddr
	tEnclaveAddr enclaveIP
	quote        *sgxQuote

	recvConn *dtls.Conn
	sendConn *dtls.Conn

	toGw   chan<- []byte
	fromGw <-chan []byte

	wg     sync.WaitGroup
	tunIdx *tunnelIndex
}

func (appTun *appTunnel) ClearPendingReq() {
	cliAddr := appTun.recvConn.RemoteAddr().(*net.UDPAddr)
	appTun.tunIdx.tunnelMux.Lock() // *LOCK*
	set, present := appTun.tunIdx.pendingTunnels[cliAddr.IP.String()]
	if !present {
		fmt.Println("No pending entry for client found")
		return
	}
	for i := 0; i < len(set); i++ {
		if set[i].encIP == appTun.tEnclaveAddr.String() {
			appTun.tunIdx.RemovePendingTunnel(cliAddr.IP, i)
			break
		}
	}
	appTun.tunIdx.tunnelMux.Unlock() // *UNLOCK*
}

func (appTun *appTunnel) OperateAppTunnel() {
	// [new] inform #2 tunnel welcome goroutine that we will wait for a 2nd tunnel from <remoteIP> with <sgx-quote>
	cliAddr := appTun.recvConn.RemoteAddr().(*net.UDPAddr)

	pentunCh := make(chan net.Conn, 1) // buffered
	info := pendTunInfo{
		ch:    pentunCh,
		encIP: appTun.tEnclaveAddr.String(),
		quote: appTun.quote,
	}

	appTun.tunIdx.tunnelMux.Lock() // *LOCK*

	set, present := appTun.tunIdx.pendingTunnels[cliAddr.IP.String()]
	if !present {
		fmt.Println("Mapping for IP not yet in map")
		set = make([]pendTunInfo, 0)
	}
	set = append(set, info)
	appTun.tunIdx.pendingTunnels[cliAddr.IP.String()] = set

	appTun.tunIdx.tunnelMux.Unlock() // *UNLOCK*

	// Send IP Assignment Message (through recv tunnel)
	encIPnum := binary.LittleEndian.Uint32(appTun.tEnclaveAddr.IP().To4())
	gwIPnum := binary.LittleEndian.Uint32(appTun.tunIdx.SyncGateway(appTun.tEnclaveAddr).IP.To4())
	nmNum := binary.LittleEndian.Uint32(*appTun.tunIdx.SyncNetmask(appTun.tEnclaveAddr))

	var ipAssignMsg = &seng_proto.IpAssignment{
		GwIp:    &gwIPnum,
		Ip:      &encIPnum,
		Netmask: &nmNum,
	}
	fmt.Println("IP Assignment Message:", &ipAssignMsg)

	out, err := proto.Marshal(ipAssignMsg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to marsal demo msg:", err)
		// TODO: how notify others?
		appTun.recvConn.Close()
		appTun.ClearPendingReq()
		close(pentunCh)
		return
	}

	var nsent int
	nsent, err = appTun.recvConn.Write(out)
	if nsent != len(out) {
		fmt.Fprintln(os.Stderr, "Failed to sent full IPAssignMsg")
		// TODO: how notify others?
		appTun.recvConn.Close()
		appTun.ClearPendingReq()
		close(pentunCh)
		return
	}

	// Receive IP Assignment ACK Msg (recv tunnel)
	buffer := make([]byte, 1500)
	var nread int
	nread, err = appTun.recvConn.Read(buffer)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to receive IP ACK msg from client")
		appTun.recvConn.Close()
		appTun.ClearPendingReq()
		close(pentunCh) // TODO: what happens if buffered message inside?
		return
	}
	cliAck := &seng_proto.IpAssignACK{}
	if err = proto.Unmarshal(buffer[:nread], cliAck); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to parse client's ACK msg")
		appTun.recvConn.Close()
		appTun.ClearPendingReq()
		close(pentunCh) // TODO: what happens if buffered message inside?
		return
	}

	// listen on channel for #2 tunnel connection with timeout
	toSecs := time.Duration(30)
	fmt.Printf("Going to wait for #2 tunnel connection (timeout: %d seconds)\n", toSecs)
	toC := make(chan bool, 1)
	go func(c chan<- bool, to time.Duration) {
		time.Sleep(time.Second * to)
		c <- true
		close(c) // TODO: could this channel leak on non-timeout bcs. of the stuck "true" value?
	}(toC, toSecs)
	select {
	case c := <-pentunCh:
		appTun.sendConn = c.(*dtls.Conn)
		close(pentunCh) // TODO: Could sender close instead? What would happen with buffered message?
	case <-toC:
		fmt.Fprintln(os.Stderr, "Timeout while waiting for #2 tunnel")
		appTun.recvConn.Close()
		appTun.ClearPendingReq()
		close(pentunCh)
		return
	}

	// start the forwarding loops
	fmt.Println("Going to start forwarding loops now")
	quitC := make(chan bool, 1)
	appTun.wg.Add(2)
	go appTun.HandleAppPackets(&appTun.wg, quitC)
	go appTun.HandleGwPackets(&appTun.wg, quitC)
	appTun.wg.Wait()

	fmt.Println("Closing App Tunnel with EnclaveIP:", appTun.tEnclaveAddr)
	// also removes the channel mapping that was used by the gateway
	appTun.tunIdx.SyncFreeIP(appTun.tEnclaveAddr)
}

func (appTun *appTunnel) HandleAppPackets(wg *sync.WaitGroup, qc chan<- bool) {
	defer wg.Done()
	for {
		buffer := make([]byte, 1500)
		nread, err := appTun.recvConn.Read(buffer)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			if err == io.EOF {
				fmt.Println("App Tunnel close notification!")
				appTun.recvConn.Close()
				// TODO: notify #2 tunnel!
				qc <- true
				break
			}
			continue
		}
		packet := buffer[:nread]
		//fmt.Println("Received client packet:", packet)

		/* Check for enclave IP spoofing */
		var hdr *ipv4.Header
		hdr, err = ipv4.ParseHeader(packet)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to parse IPv4 header of application packet. Drop.")
			continue // TODO: close?
		}
		if !hdr.Src.Equal(appTun.tEnclaveAddr.IP()) {
			fmt.Fprintf(os.Stderr, "Enclave IP mismatch detected -- expected: %s, but source IP is: %s. Drop.\n", appTun.tEnclaveAddr, hdr.Src)
			continue // TODO: close application tunnel?
		}

		// pass to gateway interface
		appTun.toGw <- packet
	}
}

func (appTun *appTunnel) HandleGwPackets(wg *sync.WaitGroup, qc <-chan bool) {
	defer wg.Done()

	//	for ipPacket := range appTun.fromGw {
Loop:
	for {
		select {

		/* quit notification */
		case <-qc:
			fmt.Println("Quit tunnel #2")
			appTun.sendConn.Close()
			break Loop

		/* recv loop (gateway, tun) */
		case ipPacket := <-appTun.fromGw:
			//fmt.Println("Received gateway packet:", ipPacket)
			nsent, err := appTun.sendConn.Write(ipPacket)
			if err != nil {
				fmt.Fprint(os.Stderr, err)
				// TODO: notify other tunnel? close this tunnel?
				continue
			}
			if nsent < len(ipPacket) {
				fmt.Fprintln(os.Stderr, "Warning: only sent", nsent, "of", len(ipPacket), "Bytes")
			}

		}
	}
}
