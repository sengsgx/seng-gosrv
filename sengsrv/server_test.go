package main

import "testing"

var goodSrvConfig = serverConfig{
	address:       "127.0.0.1:12345",
	dbPath:        "",
	useNetfltrExt: false,
	useShadowing:  false,
}

func TestInitSuccess(t *testing.T) {
	var server sengServer
	err := server.Init(goodSrvConfig)
	if err != nil {
		t.Error(err)
	}
}

func TestInitBadPort(t *testing.T) {
	badPort := "1234500000"
	var srvConfig = serverConfig{
		address:       "127.0.0.1:" + badPort,
		dbPath:        "",
		useNetfltrExt: false,
		useShadowing:  false,
	}

	var server sengServer
	err := server.Init(srvConfig)
	if err == nil {
		t.Error("Failed to detect bad port:", badPort)
	}
}

func TestInitBadIP(t *testing.T) {
	badIP := "1270.0.0.1111"
	var srvConfig = serverConfig{
		address:       badIP + ":12345",
		dbPath:        "",
		useNetfltrExt: false,
		useShadowing:  false,
	}

	var server sengServer
	err := server.Init(srvConfig)
	if err == nil {
		t.Error("Failed to detect bad IP:", badIP)
	}
}

func TestInitOpenCloseSuccess(t *testing.T) {
	var server sengServer
	err := server.Init(goodSrvConfig)
	if err != nil {
		t.Error(err)
	}

	err = server.Open()
	if err != nil {
		t.Error(err)
	}

	err = server.Close()
	if err != nil {
		t.Error(err)
	}
}

func TestOpenNoInit(t *testing.T) {
	var server sengServer
	err := server.Open()
	if err == nil {
		t.Error("Failed to detect uninitialized open attempt")
	}
	defer server.Close()
}

func TestEmptyClose(t *testing.T) {
	var server sengServer
	err := server.Close()
	if err != nil {
		t.Error(err)
	}
}
