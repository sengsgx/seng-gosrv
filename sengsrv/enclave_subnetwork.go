package main

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
)

// EnclaveSubnetwork represents an Enclave Subnetwork.
type EnclaveSubnetwork interface {
	UID() int
	GetIP() (*net.IPAddr, error)
	PutIP(*net.IPAddr)
	Gateway() *net.IPAddr
	Netmask() *net.IPMask
}

type enclaveSubnetwork struct {
	mux       sync.Mutex
	uid       int
	subnet    net.IPNet
	gateway   net.IPAddr
	nextCli   int
	cliBitset []bool
}

func (encNet *enclaveSubnetwork) UID() int {
	return encNet.uid
}

func (encNet *enclaveSubnetwork) String() (str string) {
	encNet.mux.Lock()
	defer encNet.mux.Unlock()
	str = encNet.subnet.String()
	str += " (gateway: " + encNet.gateway.String()
	str += ", cliBitset size: " + strconv.FormatInt(int64(len(encNet.cliBitset)), 10) + ")"
	return
}

func (encNet *enclaveSubnetwork) Gateway() *net.IPAddr {
	return &encNet.gateway
}

func (encNet *enclaveSubnetwork) Netmask() *net.IPMask {
	return &encNet.subnet.Mask
}

func (encNet *enclaveSubnetwork) GetIP() (ip *net.IPAddr, err error) {
	encNet.mux.Lock()
	defer encNet.mux.Unlock()
	baseIP := encNet.subnet.IP.Mask(encNet.subnet.Mask).To16()

	// if nextCli is already in use, look for other free slot
	if encNet.cliBitset[encNet.nextCli] {
		found := false
		for i := ((encNet.nextCli + 1) % 256); i != encNet.nextCli; i = ((i + 1) % 256) {
			if !(encNet.cliBitset[i]) {
				encNet.nextCli = i
				found = true
				break
			}
		}
		if !found {
			err = errors.New("Out of free enclave IPs")
			return
		}
	}

	// craft enclave IP
	ip = &net.IPAddr{
		IP: net.IPv4(baseIP[(15-3)],
			baseIP[(15-2)],
			baseIP[(15-1)],
			byte(encNet.nextCli)),
	}

	fmt.Println("New enclave IP:", ip)
	fmt.Println("Slot:", encNet.nextCli)

	encNet.cliBitset[encNet.nextCli] = true
	encNet.nextCli = (encNet.nextCli + 1) % 256
	return
}

func (encNet *enclaveSubnetwork) PutIP(ip *net.IPAddr) {
	encNet.mux.Lock()
	defer encNet.mux.Unlock()

	slt := ip.IP.To16()[15]
	fmt.Println("Freeing enclave IP:", ip)
	fmt.Println("Slot:", slt)
	encNet.cliBitset[slt] = false
}
