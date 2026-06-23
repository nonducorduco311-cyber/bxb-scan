//go:build windows

package main

import "strings"

// arpTable parses `arp -a`. Reads the existing cache; sends no packets.
func arpTable() []arpEntry {
	out := []arpEntry{}
	txt, ok := run("arp", "-a")
	if !ok {
		return out
	}
	for _, ln := range strings.Split(txt, "\n") {
		f := strings.Fields(ln)
		if len(f) < 2 {
			continue
		}
		ip, mac := f[0], f[1]
		// IPv4 dotted-quad + MAC with dashes (xx-xx-xx-xx-xx-xx)
		if strings.Count(ip, ".") == 3 && strings.Count(mac, "-") == 5 {
			out = append(out, arpEntry{IP: ip, MAC: strings.ReplaceAll(mac, "-", ":")})
		}
	}
	return out
}
