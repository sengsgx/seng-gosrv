// +build linux

package main

import (
	"github.com/songgao/water" // tuntap
)

func (gwIf *gatewayIf) InitTUN() {
	var osParams = water.PlatformSpecificParams{
		Name:    "tunFA",
		Persist: true,
		//		MultiQueue: true,
	}
	gwIf.tunConfig = water.Config{
		DeviceType:             water.TUN,
		PlatformSpecificParams: osParams,
	}
	return
}
