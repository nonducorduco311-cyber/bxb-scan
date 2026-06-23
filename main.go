package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	toolName = "ByTE X Bit Posture Scanner"
	stage    = "host + passive network"
)

// version is stamped at build time via -ldflags "-X main.version=...".
// It defaults to "dev" for a plain `go build`.
var version = "dev"

// versionLine is what the report prints.
func versionLine() string { return version + " (" + stage + ")" }

// small int helpers used across files (kept here so both build tags get them).
func itoa(n int) string { return strconv.Itoa(n) }
func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func main() {
	htmlOut := flag.String("html", "", "also write a local HTML report to this path (e.g. report.html)")
	noColor := flag.Bool("no-color", false, "disable colored terminal output")
	noPause := flag.Bool("no-pause", false, "do not wait for a keypress before exiting (for scripts)")
	network := flag.Bool("network", false, "also run passive local-network discovery (ARP cache + SSDP; no port scanning)")
	flag.Parse()

	host := baseHostInfo()
	enrichHost(&host)

	r := &Report{
		Tool:    toolName,
		Version: versionLine(),
		When:    time.Now().Format("2006-01-02 15:04:05"),
		Host:    host,
	}

	collect(r) // platform-specific host checks
	if *network {
		runNetwork(r) // passive discovery, opt-in
	}
	r.sortFindings()

	renderTerminal(r, !*noColor)

	if *htmlOut != "" {
		if err := writeHTML(r, *htmlOut); err != nil {
			fmt.Fprintf(os.Stderr, "\ncould not write HTML report: %v\n", err)
		} else {
			fmt.Printf("\nLocal HTML report written to: %s\n", *htmlOut)
		}
	}

	// On Windows a double-clicked console app closes the instant it exits.
	// Pausing here (always, unless --no-pause) guarantees the window stays open
	// long enough to read the report. On Linux/macOS this is a no-op.
	pauseBeforeExit(*noPause)
}

// ----- terminal rendering -----

const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cDim    = "\033[2m"
	cRed    = "\033[31m"
	cYellow = "\033[33m"
	cGreen  = "\033[32m"
	cBlue   = "\033[34m"
	cCyan   = "\033[36m"
)

func renderTerminal(r *Report, color bool) {
	c := func(code, s string) string {
		if !color {
			return s
		}
		return code + s + cReset
	}

	fmt.Println()
	fmt.Println(c(cBold+cCyan, "  "+r.Tool))
	fmt.Println(c(cDim, "  "+r.Version+"   "+r.When))
	fmt.Println(c(cDim, "  All results are shown here only. Nothing is sent anywhere."))
	fmt.Println()
	fmt.Printf("  %-10s %s\n", c(cDim, "Host"), r.Host.Hostname)
	fmt.Printf("  %-10s %s (%s, %s)\n", c(cDim, "System"), r.Host.OSName, r.Host.OS, r.Host.Arch)
	if r.Host.Kernel != "" {
		fmt.Printf("  %-10s %s\n", c(cDim, "Version"), r.Host.Kernel)
	}
	fmt.Printf("  %-10s %s\n", c(cDim, "User"), r.Host.User)

	fail, warn, ok, info := r.counts()
	score := r.score()
	scoreColor := cGreen
	switch {
	case score < 50:
		scoreColor = cRed
	case score < 80:
		scoreColor = cYellow
	}
	fmt.Println()
	fmt.Printf("  %s   %s\n",
		c(cBold+scoreColor, fmt.Sprintf("Posture score: %d/100", score)),
		c(cDim, fmt.Sprintf("(%d fail, %d warn, %d ok, %d info)", fail, warn, ok, info)),
	)
	fmt.Println(c(cDim, "  "+strings.Repeat("-", 60)))

	badge := func(s Status) string {
		switch s {
		case StatusFail:
			return c(cBold+cRed, "[FAIL]")
		case StatusWarn:
			return c(cBold+cYellow, "[WARN]")
		case StatusOK:
			return c(cGreen, "[ OK ]")
		default:
			return c(cBlue, "[INFO]")
		}
	}

	lastCat := ""
	for _, f := range r.Findings {
		if f.Category != lastCat {
			fmt.Println()
			fmt.Println("  " + c(cBold, f.Category))
			lastCat = f.Category
		}
		fmt.Printf("    %s %s\n", badge(f.Status), f.Title)
		if f.Detail != "" {
			fmt.Printf("           %s\n", c(cDim, f.Detail))
		}
		if f.Why != "" {
			fmt.Printf("           %s %s\n", c(cDim, "why:"), f.Why)
		}
		if f.Fix != "" {
			fmt.Printf("           %s %s\n", c(cBold, "fix:"), f.Fix)
		}
	}

	if r.NetworkScanned {
		fmt.Println()
		fmt.Println("  " + c(cBold, "Network — devices discovered (passive)"))
		if r.Subnet != "" {
			fmt.Println("  " + c(cDim, "scope: "+r.Subnet))
		}
		if len(r.Devices) == 0 {
			fmt.Println("    " + c(cDim, "No devices found (ARP cache empty or network quiet)."))
		} else {
			for _, d := range r.Devices {
				line := "    " + d.IP
				if d.MAC != "" {
					line += "   " + d.MAC
				}
				fmt.Println(line)
				extras := []string{d.Source}
				if d.Vendor != "" {
					extras = append(extras, d.Vendor)
				}
				if d.Info != "" {
					extras = append(extras, d.Info)
				}
				fmt.Println("           " + c(cDim, strings.Join(extras, " · ")))
			}
		}
	}

	fmt.Println()
	fmt.Println(c(cDim, "  "+strings.Repeat("-", 60)))
	if fail > 0 || warn > 0 {
		fmt.Println(c(cBold, "  Start with the FAIL items, then the WARNs."))
	} else {
		fmt.Println(c(cGreen, "  No issues flagged. Re-check after any major change."))
	}
	if r.NetworkScanned {
		fmt.Println(c(cDim, "  Network discovery was passive (ARP cache + SSDP). No ports were scanned."))
	} else {
		fmt.Println(c(cDim, "  Host-only check. Add --network for passive local-network discovery."))
	}
	fmt.Println()
}
