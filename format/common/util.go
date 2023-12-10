package common

import (
	"fmt"
	"net"
	"strings"
)

var (
	netInterfaces []net.Interface
)

func parseAddrIP(addr net.Addr) net.IP {
	ipStr := strings.SplitN(addr.String(), "/", 2)[0]
	ip := net.ParseIP(ipStr)
	if ip == nil {
		fmt.Printf("Error translating address '%v' to IP\n", ipStr)
	}
	return ip
}

func parseIPNet(ip *net.IP) *net.IPNet {
	cidr, _ := ip.DefaultMask().Size()
	_, ipNet, err := net.ParseCIDR(fmt.Sprintf("%v/%v", ip.String(), cidr))
	if err != nil {
		_, ipNet, _ = net.ParseCIDR("0.0.0.0/32")
	}
	return ipNet
}

func initInterfaces() {
	if netInterfaces == nil {
		nics, err := net.Interfaces()
		if err != nil {
			return
		}
		netInterfaces = nics
	}
}

func isLocalIP(checkIp net.IP) (bool, *net.Interface) {
	if checkIp == nil {
		return false, &net.Interface{}
	}

	if checkIp.String() == "127.0.0.1" || checkIp.String() == "::1" {
		nic, err := net.InterfaceByName("lo")
		if err == nil {
			return true, nic
		}
	}

	if netInterfaces == nil {
		initInterfaces()
		if netInterfaces == nil {
			return false, &net.Interface{}
		}
	}

	for _, nic := range netInterfaces {
		if !strings.Contains(nic.Flags.String(), "up") {
			continue
		}
		nicAddrs, err := nic.Addrs()

		if err != nil {
			continue
		}
		for _, nicAddr := range nicAddrs {
			nicIP := parseAddrIP(nicAddr)
			if nicIP == nil {
				continue
			}

			if nicIP.String() == checkIp.String() {
				return true, &nic
			}
		}
	}
	return false, &net.Interface{}
}

func isLocalNet(checkIp *net.IP) (bool, *net.Interface) {
	if checkIp == nil {
		return false, &net.Interface{}
	}

	if netInterfaces == nil {
		initInterfaces()
		if netInterfaces == nil {
			return false, &net.Interface{}
		}
	}

	checkNet := parseIPNet(checkIp)

	for _, nic := range netInterfaces {
		if !strings.Contains(nic.Flags.String(), "up") {
			continue
		}

		nicAddrs, err := nic.Addrs()

		if err != nil {
			continue
		}
		for _, nicAddr := range nicAddrs {
			nicIP := parseAddrIP(nicAddr)
			if nicIP == nil {
				continue
			}

			if checkNet.Contains(nicIP) {
				return true, &nic
			}
		}
	}
	return false, &net.Interface{}
}
