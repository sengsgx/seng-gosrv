package main

import (
	"fmt"
	"os"
	"sync"

	"golang.org/x/net/ipv4"

	"github.com/songgao/water" // tuntap
)

type gatewayIf struct {
	tunConfig    water.Config
	tunInterface *water.Interface
	ipFromAppsC  chan []byte
	tunIdx       *tunnelIndex
}

func (gwIf *gatewayIf) Init(tunnelIdx *tunnelIndex) {
	gwIf.InitTUN()
	gwIf.tunIdx = tunnelIdx
	gwIf.ipFromAppsC = make(chan []byte, 128)
}

func (gwIf *gatewayIf) Open() (err error) {
	gwIf.tunInterface, err = water.New(gwIf.tunConfig)
	if err != nil {
		return err
	}
	return
}

func (gwIf *gatewayIf) Close() (err error) {
	if gwIf.tunInterface != nil {
		err = gwIf.tunInterface.Close()
		gwIf.tunInterface = nil
	}
	return
}

func (gwIf *gatewayIf) appRecvLoop(wg *sync.WaitGroup) {
	defer wg.Done()
	for appPacket := range gwIf.ipFromAppsC {
		// Pass to gateway via TUN interface
		nsent, err := gwIf.tunInterface.Write(appPacket)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			// TODO: close TUN? (how notify other goroutine?)
			gwIf.tunInterface.Close()
			break
		}
		if nsent != len(appPacket) {
			fmt.Fprintln(os.Stderr, "Failed to pass full packet to the gateway")
			continue
		}
	}
}

func (gwIf *gatewayIf) tunRecvLoop(wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		buffer := make([]byte, 1500)
		nread, err := gwIf.tunInterface.Read(buffer)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			// TODO: close TUN? (how notify other goroutine?)
			gwIf.tunInterface.Close()
			break
		}
		gwPacket := buffer[:nread]

		// Parse enclave IP out of header (destination IP)
		hdr, err := ipv4.ParseHeader(gwPacket)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Received malformed IP packet from gateway. Drop.")
			continue
		}

		// Pass to respective appTunnel
		gwIf.tunIdx.rwMux.RLock() // *LOCK*
		ch, present := gwIf.tunIdx.encIPtoTunnelC[hdr.Dst.String()]
		gwIf.tunIdx.rwMux.RUnlock() // *UNLOCK*
		if !present {
			fmt.Fprintln(os.Stderr, "Destination (", hdr.Dst, ") is not an active enclave IP. Drop.")
			continue
		}
		ch <- gwPacket // TODO: can this channel become closed?!
	}
}

func (gwIf *gatewayIf) RunLoop() {
	var wg sync.WaitGroup
	wg.Add(2)
	go gwIf.tunRecvLoop(&wg)
	go gwIf.appRecvLoop(&wg)
	wg.Wait()
}

func (gwIf *gatewayIf) Channel() chan<- []byte {
	return gwIf.ipFromAppsC
}
