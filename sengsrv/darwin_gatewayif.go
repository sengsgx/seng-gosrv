// +build darwin

package main

import (
	"github.com/songgao/water" // tuntap
)

func (gwIf *gatewayIf) InitTUN() (err error) {
	var osParams = water.PlatformSpecificParams{
		Name: "utun5", // TODO
	}

	gwIf.tunConfig = water.Config{
		DeviceType:             water.TUN,
		PlatformSpecificParams: osParams,
	}
	return
}
