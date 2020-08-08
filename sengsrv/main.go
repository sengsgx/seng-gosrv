package main

import (
	"flag"
	"fmt"
	"os"
	"path"
	"sync"
)

const cliArgs = `Arguments:
    tunnel_ipv4     = IPv4 address on which the server will listen
    tunnel_port     = UDP port on which the server will listen`

func main() {
	/* CLI option and arguments parsing */
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options] <tunnel_ipv4> <tunnel_port>\n", path.Base(os.Args[0]))
		fmt.Fprintln(flag.CommandLine.Output(), "\n"+cliArgs)
		fmt.Fprintln(flag.CommandLine.Output(), "\n"+"Options:")
		flag.PrintDefaults()
	}

	dbPathPtr := flag.String("db", "", "optional path to SQLite3 database")
	sengNetfltrPtr := flag.Bool("netfilter", false, "use SENG Netfilter Extension for rule enforcement (requires --db)")
	shdwSrvPtr := flag.Bool("shadowing", false, "enable ShadowServer for auto-nat/port shadowing at 192.168.28.1:2409/tcp")

	certPathPtr := flag.String("cert", "", "server certificate path (only ECDSA)")
	keyPathPtr := flag.String("key", "", "server private key path (only ECDSA)")

	flag.Parse()

	argc := len(flag.Args())
	if argc != 2 {
		fmt.Fprintln(flag.CommandLine.Output(), "invalid number of arguments:", argc)
		flag.Usage()
		os.Exit(2)
	}

	srvAddr := flag.Args()[0] + ":" + flag.Args()[1]

	/* MAIN */
	fmt.Println("Welcome to the SENG Server (Go)")

	certPath, keyPath := "", ""
	if certPathPtr != nil {
		certPath = *certPathPtr
	}
	if keyPathPtr != nil {
		keyPath = *keyPathPtr
	}

	/* Server Configuration */
	var srvConfig = serverConfig{
		address:       srvAddr,
		dbPath:        *dbPathPtr,
		useNetfltrExt: *sengNetfltrPtr,
		useShadowing:  *shdwSrvPtr,
		certPath:      certPath,
		keyPath:       keyPath,
	}

	server := new(sengServer)
	err := server.Init(srvConfig)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to init SENG Server:\n", err)
		os.Exit(3)
	}

	/* Bind Tunnel Sockets */
	err = server.Open()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer server.Close()

	/* Start Server loop and wait for its termination */
	var wg sync.WaitGroup
	wg.Add(1)
	go server.ServerLoop(&wg)

	wg.Wait()

	fmt.Println("The SENG Server has stopped")
}
