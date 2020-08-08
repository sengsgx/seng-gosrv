package main

import "testing"

func TestGWIfInit(t *testing.T) {
	gwIf := gatewayIf{}
	gwIf.Init(nil)
}

func TestGWIfOpenClose(t *testing.T) {
	gwIf := gatewayIf{}
	gwIf.Init(nil)
	if err := gwIf.Open(); err != nil {
		t.Error(err)
	}
	if err := gwIf.Close(); err != nil {
		t.Error(err)
	}
}
