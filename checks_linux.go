//go:build linux

package main

import (
	"os"
	"strings"
)

// enrichHost adds Linux-specific identity (distro name, kernel).
func enrichHost(h *HostInfo) {
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		kv := parseKV(string(data))
		if v := kv["PRETTY_NAME"]; v != "" {
			h.OSName = v
		}
	}
	if h.OSName == "" {
		h.OSName = "Linux"
	}
	if k, ok := run("uname", "-r"); ok {
		h.Kernel = k
	}
}

// collect runs all Linux checks and appends findings to the report.
func collect(r *Report) {
	checkLinuxFirewall(r)
	checkLinuxDiskEncryption(r)
	checkLinuxAutoUpdates(r)
	checkLinuxSudoers(r)
	checkLinuxSSH(r)
	checkLinuxPackages(r)
	checkLinuxPendingUpdates(r)
}

func parseKV(s string) map[string]string {
	m := map[string]string{}
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if i := strings.IndexByte(ln, '='); i > 0 {
			k := ln[:i]
			v := strings.Trim(ln[i+1:], `"'`)
			m[k] = v
		}
	}
	return m
}

func checkLinuxFirewall(r *Report) {
	// ufw
	if have("ufw") {
		if out, ok := run("ufw", "status"); ok {
			if containsFold(out, "Status: active") {
				r.add(Finding{Category: "Network", Title: "Host firewall", Status: StatusOK,
					Detail: "ufw firewall is active."})
				return
			}
			r.add(Finding{Category: "Network", Title: "Host firewall", Status: StatusWarn,
				Detail: "ufw is installed but not active.",
				Why:    "Without a host firewall, services on this machine are reachable by anything that can route to it.",
				Fix:    "Enable it with: sudo ufw enable (after allowing the ports you actually need)."})
			return
		}
	}
	// firewalld
	if have("firewall-cmd") {
		if out, ok := run("firewall-cmd", "--state"); ok && containsFold(out, "running") {
			r.add(Finding{Category: "Network", Title: "Host firewall", Status: StatusOK,
				Detail: "firewalld is running."})
			return
		}
	}
	// iptables presence as a last hint
	if have("iptables") {
		if out, ok := run("iptables", "-S"); ok {
			rules := 0
			for _, ln := range strings.Split(out, "\n") {
				if strings.HasPrefix(ln, "-A") {
					rules++
				}
			}
			if rules > 0 {
				r.add(Finding{Category: "Network", Title: "Host firewall", Status: StatusInfo,
					Detail: "iptables rules are present, but no managed firewall (ufw/firewalld) was detected."})
				return
			}
		}
	}
	r.add(Finding{Category: "Network", Title: "Host firewall", Status: StatusWarn,
		Detail: "No active host firewall detected.",
		Why:    "A host firewall limits what can reach this machine's services from the network.",
		Fix:    "Install and enable ufw (Debian/Ubuntu) or firewalld (RHEL/Fedora)."})
}

func checkLinuxDiskEncryption(r *Report) {
	if !have("lsblk") {
		return
	}
	if out, ok := run("lsblk", "-o", "TYPE"); ok {
		if containsFold(out, "crypt") {
			r.add(Finding{Category: "Data & Recovery", Title: "Disk encryption", Status: StatusOK,
				Detail: "An encrypted (LUKS/crypt) block device is present."})
			return
		}
	}
	r.add(Finding{Category: "Data & Recovery", Title: "Disk encryption", Status: StatusWarn,
		Detail: "No encrypted block device detected.",
		Why:    "If this machine is lost or stolen, unencrypted drives expose all their data.",
		Fix:    "Use full-disk encryption (LUKS). It is easiest to enable at install time."})
}

func checkLinuxAutoUpdates(r *Report) {
	// Debian/Ubuntu unattended-upgrades
	if _, err := os.Stat("/etc/apt/apt.conf.d/20auto-upgrades"); err == nil {
		data, _ := os.ReadFile("/etc/apt/apt.conf.d/20auto-upgrades")
		if containsFold(string(data), `"1"`) {
			r.add(Finding{Category: "Devices & Updates", Title: "Automatic updates", Status: StatusOK,
				Detail: "Unattended security upgrades appear to be enabled."})
			return
		}
	}
	if have("dnf") {
		if out, ok := run("systemctl", "is-enabled", "dnf-automatic.timer"); ok && containsFold(out, "enabled") {
			r.add(Finding{Category: "Devices & Updates", Title: "Automatic updates", Status: StatusOK,
				Detail: "dnf-automatic timer is enabled."})
			return
		}
	}
	r.add(Finding{Category: "Devices & Updates", Title: "Automatic updates", Status: StatusWarn,
		Detail: "Automatic security updates do not appear to be enabled.",
		Why:    "Unpatched software is the most common way machines get compromised.",
		Fix:    "Enable unattended-upgrades (Debian/Ubuntu) or dnf-automatic (Fedora/RHEL), or set a regular patch routine."})
}

func checkLinuxSudoers(r *Report) {
	out, ok := run("getent", "group", "sudo")
	if !ok || out == "" {
		out, ok = run("getent", "group", "wheel")
	}
	if !ok || out == "" {
		return
	}
	// format: sudo:x:27:alice,bob
	parts := strings.SplitN(out, ":", 4)
	members := ""
	if len(parts) == 4 {
		members = parts[3]
	}
	n := 0
	if strings.TrimSpace(members) != "" {
		n = len(strings.Split(members, ","))
	}
	if n > 3 {
		r.add(Finding{Category: "Accounts & Access", Title: "Administrative accounts", Status: StatusWarn,
			Detail: "Several accounts have administrative (sudo) rights: " + members,
			Why:    "Every admin account widens the blast radius if one is compromised.",
			Fix:    "Review the list and remove admin rights from anyone who doesn't need them."})
		return
	}
	r.add(Finding{Category: "Accounts & Access", Title: "Administrative accounts", Status: StatusOK,
		Detail: "Administrative access is limited to a small set of accounts."})
}

func checkLinuxSSH(r *Report) {
	data, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return // ssh server not configured; nothing to flag
	}
	cfg := strings.ToLower(string(data))
	if strings.Contains(cfg, "permitrootlogin yes") {
		r.add(Finding{Category: "Accounts & Access", Title: "SSH root login", Status: StatusFail,
			Detail: "SSH is configured to permit direct root login.",
			Why:    "Direct root login over SSH is a prime brute-force target and removes accountability.",
			Fix:    "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and use a normal account with sudo."})
		return
	}
	if strings.Contains(cfg, "passwordauthentication yes") {
		r.add(Finding{Category: "Accounts & Access", Title: "SSH password auth", Status: StatusWarn,
			Detail: "SSH allows password authentication.",
			Why:    "Password-based SSH is exposed to brute-force and credential-stuffing.",
			Fix:    "Prefer key-based auth and set 'PasswordAuthentication no' once keys are in place."})
		return
	}
	r.add(Finding{Category: "Accounts & Access", Title: "SSH configuration", Status: StatusOK,
		Detail: "SSH does not permit root login or password auth (or both are disabled)."})
}

func checkLinuxPackages(r *Report) {
	if have("dpkg-query") {
		if out, ok := run("dpkg-query", "-f", "${binary:Package}\n", "-W"); ok {
			n := countNonEmpty(out)
			r.add(Finding{Category: "System", Title: "Installed packages", Status: StatusInfo,
				Detail: itoa(n) + " packages installed (dpkg)."})
			return
		}
	}
	if have("rpm") {
		if out, ok := run("rpm", "-qa"); ok {
			n := countNonEmpty(out)
			r.add(Finding{Category: "System", Title: "Installed packages", Status: StatusInfo,
				Detail: itoa(n) + " packages installed (rpm)."})
			return
		}
	}
}

func checkLinuxPendingUpdates(r *Report) {
	if have("apt-get") {
		// -s = simulate, no changes made
		if out, ok := run("apt-get", "-s", "upgrade"); ok {
			n := 0
			for _, ln := range strings.Split(out, "\n") {
				if strings.HasPrefix(ln, "Inst ") {
					n++
				}
			}
			if n > 0 {
				st := StatusWarn
				if n > 30 {
					st = StatusFail
				}
				r.add(Finding{Category: "Devices & Updates", Title: "Pending updates", Status: st,
					Detail: itoa(n) + " package updates are available.",
					Why:    "Available-but-uninstalled updates often include security fixes for known, exploited bugs.",
					Fix:    "Apply them with: sudo apt-get update && sudo apt-get upgrade."})
				return
			}
			r.add(Finding{Category: "Devices & Updates", Title: "Pending updates", Status: StatusOK,
				Detail: "No pending package updates detected."})
		}
	}
}

func countNonEmpty(s string) int {
	n := 0
	for _, ln := range strings.Split(s, "\n") {
		if strings.TrimSpace(ln) != "" {
			n++
		}
	}
	return n
}
