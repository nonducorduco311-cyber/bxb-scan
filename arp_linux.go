//go:build linux

package main

import (
	"os"
	"strings"
)

// arpTable reads the kernel ARP cache. No packets are sent.
func arpTable() []arpEntry {
	out := []arpEntry{}
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return out
	}
	for i, ln := range strings.Split(string(data), "\n") {
		if i == 0 { // header row
			continue
		}
		f := strings.Fields(ln)
		if len(f) < 4 {
			continue
		}
		ip, mac := f[0], f[3]
		if mac == "00:00:00:00:00:00" || mac == "" {
			continue // incomplete entry
		}
		out = append(out, arpEntry{IP: ip, MAC: mac})
	}
	return out
}
