package main

import (
	"net"
	"sort"
	"strings"
	"time"
)

// arpEntry is one IP↔MAC mapping from the OS neighbor cache.
// (arpTable is implemented per-OS in arp_linux.go / arp_windows.go.)
type arpEntry struct {
	IP  string
	MAC string
}

// Small, conservative OUI map — only prefixes we're confident about. Most
// useful in virtualized environments; blank when unknown rather than guessing.
var oui = map[string]string{
	"525400": "QEMU/KVM virtual",
	"080027": "VirtualBox virtual",
	"000C29": "VMware virtual",
	"005056": "VMware virtual",
	"001C14": "VMware virtual",
	"00155D": "Hyper-V virtual",
	"BC2411": "Proxmox virtual",
	"B827EB": "Raspberry Pi",
	"DCA632": "Raspberry Pi",
	"E45F01": "Raspberry Pi",
	"28CDC1": "Raspberry Pi",
}

func normMAC(m string) string {
	return strings.NewReplacer(":", "", "-", "", ".", "").Replace(strings.ToUpper(m))
}

func vendorFor(mac string) string {
	n := normMAC(mac)
	if len(n) >= 6 {
		if v, ok := oui[n[:6]]; ok {
			return v
		}
	}
	return ""
}

// localSubnet returns the primary non-loopback IPv4 address and its CIDR.
func localSubnet() (ip, cidr string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", ""
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if v4 := ipnet.IP.To4(); v4 != nil {
					return v4.String(), ipnet.String()
				}
			}
		}
	}
	return "", ""
}

type ssdpResp struct {
	IP     string
	Server string
}

// ssdpDiscover sends one standard SSDP M-SEARCH and collects replies. This is
// ordinary service-discovery traffic (the same a phone or smart-TV emits), not
// a port scan. Any network error degrades gracefully to an empty result.
func ssdpDiscover(timeout time.Duration) []ssdpResp {
	out := []ssdpResp{}
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return out
	}
	defer conn.Close()

	msg := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: ssdp:all\r\n\r\n"
	dst := &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}
	if _, err := conn.WriteTo([]byte(msg), dst); err != nil {
		return out
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	seen := map[string]bool{}
	buf := make([]byte, 2048)
	for {
		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			break // deadline reached
		}
		host, _, _ := net.SplitHostPort(src.String())
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		server := ""
		for _, ln := range strings.Split(string(buf[:n]), "\r\n") {
			if strings.HasPrefix(strings.ToUpper(ln), "SERVER:") {
				server = strings.TrimSpace(ln[len("SERVER:"):])
			}
		}
		out = append(out, ssdpResp{IP: host, Server: server})
	}
	return out
}

func sortDevices(d []Device) {
	sort.SliceStable(d, func(i, j int) bool {
		 a, b := net.ParseIP(d[i].IP), net.ParseIP(d[j].IP)
		if a != nil && b != nil {
			return strings.Compare(string(a.To16()), string(b.To16())) < 0
		}
		return d[i].IP < d[j].IP
	})
}

// runNetwork performs passive local-network discovery and records the results.
// It never scans ports; it reads the OS ARP cache and listens for SSDP replies.
func runNetwork(r *Report) {
	r.NetworkScanned = true
	myIP, cidr := localSubnet()
	r.Subnet = cidr

	devs := map[string]*Device{}

	// 1) ARP / neighbor cache — fully passive (existing OS state, no traffic).
	for _, e := range arpTable() {
		devs[e.IP] = &Device{IP: e.IP, MAC: e.MAC, Vendor: vendorFor(e.MAC), Source: "ARP cache"}
	}

	// 2) SSDP / UPnP — standard multicast service discovery (not a port scan).
	ssdpCount := 0
	for _, s := range ssdpDiscover(3 * time.Second) {
		ssdpCount++
		if d, ok := devs[s.IP]; ok {
			d.Info = s.Server
			d.Source = "ARP + SSDP"
		} else {
			devs[s.IP] = &Device{IP: s.IP, Info: s.Server, Source: "SSDP"}
		}
	}

	for _, d := range devs {
		if d.IP == myIP {
			continue // don't list ourselves
		}
		r.Devices = append(r.Devices, *d)
	}
	sortDevices(r.Devices)

	netLabel := cidr
	if netLabel == "" {
		netLabel = "the local network"
	}
	r.add(Finding{Category: "Network discovery", Title: "Devices on your network", Status: StatusInfo,
		Detail: itoa(len(r.Devices)) + " device(s) seen on " + netLabel + " (passive — no port scanning)."})

	if ssdpCount > 0 {
		r.add(Finding{Category: "Network discovery", Title: "UPnP / SSDP is active", Status: StatusWarn,
			Detail: itoa(ssdpCount) + " device(s) respond to UPnP/SSDP discovery.",
			Why:    "UPnP lets devices open ports on your router automatically, which can quietly expose internal services to the internet.",
			Fix:    "Unless you rely on it, consider turning UPnP off on your router and review which devices use it."})
	}
}
