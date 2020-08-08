package main

import (
	"fmt"
	"net"
	"testing"
)

func TestAppTunNoIdx(t *testing.T) {
	hostAddr := net.ParseIP("127.0.0.1")
	encAddr := net.ParseIP("192.168.28.2")
	toGwC := make(chan []byte, 2)
	fromGwC := make(chan []byte, 2)
	appTun := appTunnel{
		uHostAddr:    &net.UDPAddr{IP: hostAddr, Port: 12345},
		tEnclaveAddr: enclaveIP{&net.IPAddr{IP: encAddr}, 0},
		recvConn:     nil,
		toGw:         toGwC,
		fromGw:       fromGwC,
		tunIdx:       nil,
	}
	fmt.Println(&appTun)
}

func TestAppTun(t *testing.T) {
	tunIdx := tunnelIndex{}
	tunIdx.Init("")

	hostAddr := net.ParseIP("127.0.0.1")
	encAddr := net.ParseIP("192.168.28.2")
	toGwC := make(chan []byte, 2)
	fromGwC := make(chan []byte, 2)

	appTun := appTunnel{
		uHostAddr:    &net.UDPAddr{IP: hostAddr, Port: 12345},
		tEnclaveAddr: enclaveIP{&net.IPAddr{IP: encAddr}, 0},
		recvConn:     nil,
		toGw:         toGwC,
		fromGw:       fromGwC,
		tunIdx:       &tunIdx,
	}
	fmt.Println(&appTun)
}
