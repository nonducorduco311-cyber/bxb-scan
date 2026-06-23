//go:build windows

package main

import (
	"strings"
)

// ps runs a PowerShell command and returns trimmed output.
func ps(command string) (string, bool) {
	return run("powershell", "-NoProfile", "-NonInteractive", "-Command", command)
}

// enrichHost adds Windows-specific identity.
func enrichHost(h *HostInfo) {
	if out, ok := ps(`(Get-CimInstance Win32_OperatingSystem).Caption`); ok && out != "" {
		h.OSName = strings.TrimSpace(out)
	} else {
		h.OSName = "Windows"
	}
	if out, ok := ps(`(Get-CimInstance Win32_OperatingSystem).Version`); ok {
		h.Kernel = strings.TrimSpace(out)
	}
}

// collect runs all Windows checks.
func collect(r *Report) {
	checkWinFirewall(r)
	checkWinBitLocker(r)
	checkWinDefender(r)
	checkWinUpdates(r)
	checkWinAdmins(r)
	checkWinSMB1(r)
	checkWinSoftware(r)
}

func checkWinFirewall(r *Report) {
	out, ok := ps(`(Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $false}).Name -join ','`)
	if !ok {
		return
	}
	out = strings.TrimSpace(out)
	if out == "" {
		r.add(Finding{Category: "Network", Title: "Windows Firewall", Status: StatusOK,
			Detail: "All firewall profiles (Domain, Private, Public) are enabled."})
		return
	}
	r.add(Finding{Category: "Network", Title: "Windows Firewall", Status: StatusWarn,
		Detail: "Firewall is disabled for profile(s): " + out + ".",
		Why:    "A disabled firewall profile lets the network reach this machine's services directly.",
		Fix:    "Re-enable it: Set-NetFirewallProfile -Profile " + out + " -Enabled True."})
}

func checkWinBitLocker(r *Report) {
	out, ok := ps(`try { (Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus } catch { 'ERR' }`)
	if !ok || strings.Contains(out, "ERR") {
		r.add(Finding{Category: "Data & Recovery", Title: "Disk encryption (BitLocker)", Status: StatusInfo,
			Detail: "Could not read BitLocker status (may require admin or be unsupported on this edition)."})
		return
	}
	if strings.Contains(out, "On") || strings.TrimSpace(out) == "1" {
		r.add(Finding{Category: "Data & Recovery", Title: "Disk encryption (BitLocker)", Status: StatusOK,
			Detail: "BitLocker protection is on for the system drive."})
		return
	}
	r.add(Finding{Category: "Data & Recovery", Title: "Disk encryption (BitLocker)", Status: StatusWarn,
		Detail: "BitLocker is not protecting the system drive.",
		Why:    "A lost or stolen laptop without encryption exposes every file on it.",
		Fix:    "Turn on BitLocker for the system drive (Control Panel > BitLocker Drive Encryption)."})
}

func checkWinDefender(r *Report) {
	out, ok := ps(`try { $s=Get-MpComputerStatus; "$($s.AntivirusEnabled);$($s.RealTimeProtectionEnabled);$($s.AntivirusSignatureAge)" } catch { 'ERR' }`)
	if !ok || strings.Contains(out, "ERR") {
		r.add(Finding{Category: "Devices & Updates", Title: "Endpoint protection", Status: StatusInfo,
			Detail: "Could not read Microsoft Defender status; a third-party AV may be in use."})
		return
	}
	parts := strings.Split(strings.TrimSpace(out), ";")
	av, rtp := "", ""
	if len(parts) >= 2 {
		av, rtp = parts[0], parts[1]
	}
	if containsFold(av, "true") && containsFold(rtp, "true") {
		r.add(Finding{Category: "Devices & Updates", Title: "Endpoint protection", Status: StatusOK,
			Detail: "Microsoft Defender antivirus and real-time protection are enabled."})
		return
	}
	r.add(Finding{Category: "Devices & Updates", Title: "Endpoint protection", Status: StatusWarn,
		Detail: "Defender antivirus or real-time protection appears disabled.",
		Why:    "Without active endpoint protection, malware that reaches this machine runs unchecked.",
		Fix:    "Enable Microsoft Defender real-time protection, or confirm a reputable third-party AV is active."})
}

func checkWinUpdates(r *Report) {
	// Last install date of any update as a freshness hint.
	out, ok := ps(`try { (Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn.ToString('yyyy-MM-dd') } catch { '' }`)
	if !ok || strings.TrimSpace(out) == "" {
		r.add(Finding{Category: "Devices & Updates", Title: "Windows updates", Status: StatusInfo,
			Detail: "Could not determine last update date."})
		return
	}
	r.add(Finding{Category: "Devices & Updates", Title: "Windows updates", Status: StatusInfo,
		Detail: "Most recent update installed on " + strings.TrimSpace(out) + ". Confirm Windows Update is current."})
}

func checkWinAdmins(r *Report) {
	out, ok := ps(`(Get-LocalGroupMember -Group 'Administrators' | Measure-Object).Count`)
	if !ok || strings.TrimSpace(out) == "" {
		return
	}
	n := atoiSafe(strings.TrimSpace(out))
	if n > 3 {
		r.add(Finding{Category: "Accounts & Access", Title: "Administrator accounts", Status: StatusWarn,
			Detail: itoa(n) + " accounts are members of the local Administrators group.",
			Why:    "Every local admin widens the blast radius if one account is compromised.",
			Fix:    "Review the Administrators group and remove anyone who doesn't need admin rights."})
		return
	}
	r.add(Finding{Category: "Accounts & Access", Title: "Administrator accounts", Status: StatusOK,
		Detail: "Local administrator membership is limited (" + itoa(n) + ")."})
}

func checkWinSMB1(r *Report) {
	out, ok := ps(`try { (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State } catch { 'ERR' }`)
	if !ok || strings.Contains(out, "ERR") {
		return
	}
	if containsFold(out, "Enabled") {
		r.add(Finding{Category: "Network", Title: "SMBv1 protocol", Status: StatusFail,
			Detail: "The legacy SMBv1 protocol is enabled.",
			Why:    "SMBv1 is obsolete and was the vector for WannaCry/NotPetya; it should be off everywhere.",
			Fix:    "Disable it: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol."})
		return
	}
	r.add(Finding{Category: "Network", Title: "SMBv1 protocol", Status: StatusOK,
		Detail: "Legacy SMBv1 is disabled."})
}

func checkWinSoftware(r *Report) {
	out, ok := ps(`(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName} | Measure-Object).Count`)
	if !ok || strings.TrimSpace(out) == "" {
		return
	}
	r.add(Finding{Category: "System", Title: "Installed software", Status: StatusInfo,
		Detail: strings.TrimSpace(out) + " installed programs detected."})
}

func atoiSafe(s string) int { return atoi(s) }
