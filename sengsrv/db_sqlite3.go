package main

import (
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"

	_ "github.com/mattn/go-sqlite3"
)

// SENGDatabase SENG's allowlist and subnetwork database
type SENGDatabase interface {
	Open(path string) error
	Close() error

	ParseEnclaveSubnetworks() ([]EnclaveSubnetwork, error)
	isAllowlisted(quote *sgxQuote) (bool, error)
	getAppSubnetUID(quote *sgxQuote, hostAddr *net.UDPAddr) (int, error)
}

type sqltDB struct {
	db *sql.DB
}

func (sdb *sqltDB) Open(path string) (err error) {
	sdb.db, err = sql.Open("sqlite3", path)
	return
}

func (sdb *sqltDB) Close() error {
	return sdb.db.Close()
}

// based on: https://play.golang.org/p/T5B-6RExlj [26.06.2020]
func long2ip(ipLong uint32) net.IP {
	ipByte := make([]byte, 4)
	// note: it's already BigEndian in our case, so don't swap again
	binary.LittleEndian.PutUint32(ipByte, ipLong)
	ip := net.IP(ipByte)
	return ip
}

func (sdb *sqltDB) ParseEnclaveSubnetworks() (encNets []EnclaveSubnetwork, err error) {
	/* query */
	const getSubnets = "SELECT id, subnet, submask, gateway FROM enclave_subnets;"
	rows, err := sdb.db.Query(getSubnets)
	if err != nil {
		//db.Close()
		return
	}
	defer rows.Close()

	/* parse */
	encNets = make([]EnclaveSubnetwork, 0)
	for rows.Next() {
		// TODO: int vs. uint32
		var id, subnet, submask, gateway int
		if err = rows.Scan(&id, &subnet, &submask, &gateway); err != nil {
			return
		}

		gwIP := net.IPAddr{IP: long2ip(uint32(gateway))}
		fmt.Println("gwIP:", gwIP)

		subIP := long2ip(uint32(subnet))
		fmt.Println("subIP:", subIP)

		maskBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(maskBytes, uint32(submask))
		mask := net.IPMask(maskBytes)
		fmt.Println("mask:", mask)

		subNet := net.IPNet{IP: subIP.Mask(mask), Mask: mask}

		// consistency check
		if !subNet.Contains(gwIP.IP) {
			//			db.Close()
			return nil, errors.New("Gateway IP not in subnetwork")
		}

		// number of client IPs
		fix, total := mask.Size()
		clibitSz := uint32(math.Pow(2, float64(total-fix)))
		fmt.Println("clibitSz:", clibitSz)

		/* gateway client number for blocking IP slot */
		xorMask := net.IPMask([]byte{0xff, 0xff, 0xff, 0xff})
		fmt.Println("xorMask:", xorMask)

		invMask := net.IPMask(make([]byte, len(maskBytes)))
		copy(invMask, maskBytes)
		for i, b := range xorMask {
			invMask[i] ^= b
		}
		fmt.Println("invMask:", invMask)

		gwCliNum := binary.BigEndian.Uint32(gwIP.IP.Mask(invMask).To4())
		fmt.Println("gwCliNum:", gwCliNum)

		// craft enclave subnetwork
		encNet := &enclaveSubnetwork{
			uid:       id,
			subnet:    subNet,
			gateway:   gwIP,
			nextCli:   int((gwCliNum + 1) % (clibitSz)),
			cliBitset: make([]bool, clibitSz),
		}

		// mark gateway IP as used
		encNet.cliBitset[gwCliNum] = true
		encNets = append(encNets, encNet)
		fmt.Println("Parsed enclave subnetwork:", encNet.String())
	}
	// TODO: if err = rows.Err(); err != nil {}

	return
}

func (sdb *sqltDB) isAllowlisted(quote *sgxQuote) (bool, error) {
	const checkIfAllowed = "SELECT id FROM apps WHERE mr_enclave == ?;"
	stmt, err := sdb.db.Prepare(checkIfAllowed)
	if err != nil {
		return false, err
	}
	defer stmt.Close()

	rows, err := stmt.Query(quote.ReportBody.MrEnclave.M[:])
	if err != nil {
		return false, err
	}
	defer rows.Close()

	if !rows.Next() {
		return false, nil
	}

	// app occurs at least once in database
	return true, nil
}

func (sdb *sqltDB) getAppSubnetUID(quote *sgxQuote, hostAddr *net.UDPAddr) (int, error) {
	const getAppSubnets = "SELECT enclave_subnets.id, apps.host_subnet, apps.host_submask FROM apps JOIN enclave_subnets ON apps.enc_subnet_id=enclave_subnets.id WHERE mr_enclave == ?;"

	stmt, err := sdb.db.Prepare(getAppSubnets)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	rows, err := stmt.Query(quote.ReportBody.MrEnclave.M[:])
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	for rows.Next() {
		var id, hostSubnet, hostSubmask int
		err = rows.Scan(&id, &hostSubnet, &hostSubmask)
		if err != nil {
			return 0, err
		}

		hostSubIP := long2ip(uint32(hostSubnet))
		fmt.Println("hostSubIP:", hostSubIP)

		maskBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(maskBytes, uint32(hostSubmask))
		hostMask := net.IPMask(maskBytes)
		fmt.Println("hostMask:", hostMask)

		hostSubNet := net.IPNet{IP: hostSubIP.Mask(hostMask), Mask: hostMask}
		if !hostSubNet.Contains(hostAddr.IP) {
			fmt.Println("hostSubnet:", hostSubNet, "does not contain host IP:", hostAddr.IP)
			continue
		}

		// found
		return id, nil
	}
	// TODO: if err = rows.Err(); err != nil {}

	return 0, errors.New("No matching enclave subnet found")
}
