package main

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
)

type enclaveIP struct {
	ip  *net.IPAddr
	net int
}

// convenience
func (eip enclaveIP) String() string {
	return eip.ip.String()
}

// convenience
func (eip enclaveIP) IP() net.IP {
	return eip.ip.IP
}

type pendTunInfo struct {
	ch    chan<- net.Conn
	encIP string
	quote *sgxQuote
}

type tunnelIndex struct {
	encIPtoTunnelC map[string]chan<- []byte // gwPacketC
	rwMux          sync.RWMutex

	pendingTunnels map[string][]pendTunInfo // wait for 2nd tunnel
	tunnelMux      sync.Mutex

	encNets []EnclaveSubnetwork
	sengDB  SENGDatabase
	dbPath  string
}

func (ti *tunnelIndex) SyncAllocIP(quote *sgxQuote, hostAddr *net.UDPAddr) (ip enclaveIP, err error) {
	// no -db
	if ti.dbPath == "" {
		ip.net = 0
		ip.ip, err = ti.encNets[0].GetIP()
		return
	}

	// probably redundant
	allowed, err := ti.sengDB.isAllowlisted(quote)
	if err != nil {
		return
	}
	if !allowed {
		return ip, errors.New("App not allowlisted")
	}

	// choose enclaveSubnetwork based on measurement + hostIP
	uid, err := ti.sengDB.getAppSubnetUID(quote, hostAddr)
	if err != nil {
		return ip, errors.New("Failed to alloc enclave IP: " + err.Error())
	}

	found := false
	// uid --> index
	for idx, encN := range ti.encNets {
		if encN.UID() == uid {
			ip.net = idx
			found = true
			break
		}
	}
	if !found {
		panic("Enclave Subnetwork has not been loaded! (uid: " + strconv.Itoa(uid) + ")")
	}

	ip.ip, err = ti.encNets[ip.net].GetIP()
	return
}

func (ti *tunnelIndex) SyncFreeIP(encIP enclaveIP) {
	if (encIP.net < 0) || (int(encIP.net) >= len(ti.encNets)) {
		panic("Unknown Enclave Subnetwork handle: " + strconv.Itoa(int(encIP.net)))
	}
	ti.encNets[encIP.net].PutIP(encIP.ip)

	// remove channel mapping
	ti.rwMux.Lock()
	delete(ti.encIPtoTunnelC, encIP.String())
	ti.rwMux.Unlock()
}

func (ti *tunnelIndex) SyncGateway(encIP enclaveIP) (i *net.IPAddr) {
	if (encIP.net < 0) || (int(encIP.net) >= len(ti.encNets)) {
		panic("Unknown Enclave Subnetwork handle: " + strconv.Itoa(int(encIP.net)))
	}
	return ti.encNets[encIP.net].Gateway()
}

func (ti *tunnelIndex) SyncNetmask(encIP enclaveIP) (m *net.IPMask) {
	if (encIP.net < 0) || (int(encIP.net) >= len(ti.encNets)) {
		panic("Unknown Enclave Subnetwork handle: " + strconv.Itoa(int(encIP.net)))
	}
	return ti.encNets[encIP.net].Netmask()
}

// TODO: not called
func (ti *tunnelIndex) Fini() {
	if ti.dbPath != "" {
		ti.sengDB.Close()
	}
}

func (ti *tunnelIndex) Init(dbPath string) (err error) {
	ti.encIPtoTunnelC = make(map[string]chan<- []byte)
	ti.pendingTunnels = make(map[string][]pendTunInfo)

	if dbPath != "" {
		ti.sengDB = &sqltDB{}
		if err = ti.sengDB.Open(dbPath); err != nil {
			return
		}
		if ti.encNets, err = ti.sengDB.ParseEnclaveSubnetworks(); err != nil {
			ti.sengDB.Close()
			return
		}
		ti.dbPath = dbPath
		return
	}

	/* no db given: a single 192.168.28.0/24 enclave subnetwork */
	ipnet := net.IPNet{
		IP:   net.ParseIP("192.168.28.0"),
		Mask: net.IPv4Mask(255, 255, 255, 0),
	}

	var clibit [256]bool
	clibit[0] = true
	clibit[1] = true
	clibit[255] = true

	ti.encNets = []EnclaveSubnetwork{&enclaveSubnetwork{
		subnet:    ipnet,
		gateway:   net.IPAddr{IP: net.ParseIP("192.168.28.1"), Zone: ""},
		nextCli:   2,
		cliBitset: clibit[:],
	}}

	fmt.Println("Single Enclave Subnetwork:", ti.encNets[0])
	return
}

/* Should be called by TUN proxy */
func (ti *tunnelIndex) SyncGetSendChannel(tEncAddr *net.UDPAddr) (ch chan<- []byte, present bool) {
	ti.rwMux.RLock()
	defer ti.rwMux.RUnlock()
	ch, present = ti.encIPtoTunnelC[tEncAddr.String()]
	return
}

/* Should be called by sendWelcomeLoop */
func (ti *tunnelIndex) GetPendingTunnel(uHostAddr net.IP) (infoSet []pendTunInfo, present bool) {
	infoSet, present = ti.pendingTunnels[uHostAddr.String()]
	return
}

func (ti *tunnelIndex) RemovePendingTunnel(ip net.IP, idx int) (err error) {
	infoSet, present := ti.pendingTunnels[ip.String()]
	if !present {
		return errors.New("Entry does not exist")
	}
	if (len(infoSet) - 1) < idx {
		return errors.New("Index does not exist")
	}
	// delete entire entry
	if len(infoSet) == 1 {
		delete(ti.pendingTunnels, ip.String())
		return
	}
	// only remove sub-entry
	infoSet[idx] = infoSet[len(infoSet)-1]
	ti.pendingTunnels[ip.String()] = infoSet[:len(infoSet)-1]
	return
}
