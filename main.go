package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// stdin is a single shared reader. Using one reader avoids losing buffered
// bytes between successive prompts (menu, yes/no, and the exit pause).
var stdin = bufio.NewReader(os.Stdin)

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
	htmlOut := flag.String("html", "", "write a local HTML report to this path (skips the menu)")
	noColor := flag.Bool("no-color", false, "disable colored terminal output")
	noPause := flag.Bool("no-pause", false, "do not wait for a keypress before exiting (implies --host-only, no menu)")
	network := flag.Bool("network", false, "scan host + passive local-network discovery (skips the menu)")
	hostOnly := flag.Bool("host-only", false, "scan this computer only (skips the menu)")
	flag.Parse()

	// Decide the scan scope. Flags always win and skip the interactive menu so
	// scripted/piped runs never block. Only a bare interactive run shows the menu.
	doNetwork := false
	saveReport := *htmlOut != ""
	reportPath := *htmlOut

	switch {
	case *network:
		doNetwork = true
	case *hostOnly || *noPause:
		doNetwork = false
	case *htmlOut != "":
		// an explicit --html run is non-interactive; default to host-only
		doNetwork = false
	default:
		// no scope flag: show the menu if we have an interactive console
		choice := menuScope()
		switch choice {
		case scopeQuit:
			return
		case scopeNetwork:
			doNetwork = true
		default: // scopeHost or no-input fallback
			doNetwork = false
		}
		// offer to save a report (only in the interactive path)
		if choice != scopeQuit && askYesNo("Save an HTML report you can keep? [y/N]: ") {
			saveReport = true
			reportPath = defaultReportPath()
		}
	}

	host := baseHostInfo()
	enrichHost(&host)

	r := &Report{
		Tool:    toolName,
		Version: versionLine(),
		When:    time.Now().Format("2006-01-02 15:04:05"),
		Host:    host,
	}

	collect(r) // platform-specific host checks
	if doNetwork {
		runNetwork(r) // passive discovery, opt-in
	}
	r.sortFindings()

	renderTerminal(r, !*noColor)

	if saveReport {
		if err := writeHTML(r, reportPath); err != nil {
			fmt.Fprintf(os.Stderr, "\ncould not write HTML report: %v\n", err)
		} else {
			fmt.Printf("\n  Report saved: %s\n", reportPath)
		}
	}

	// On Windows a double-clicked console app closes the instant it exits.
	// Pausing here (always, unless --no-pause) guarantees the window stays open
	// long enough to read the report. On Linux/macOS this is a no-op.
	pauseBeforeExit(*noPause)
}

// scan-scope choices returned by the menu
const (
	scopeHost = iota
	scopeNetwork
	scopeQuit
)

// menuScope shows the interactive choice. If input can't be read (piped,
// non-interactive, no console), it safely defaults to host-only — network
// discovery is never triggered without an explicit choice.
func menuScope() int {
	fmt.Println()
	fmt.Println("  " + toolName + " " + version)
	fmt.Println()
	fmt.Println("  What would you like to scan?")
	fmt.Println("    1) This computer only            (host posture)")
	fmt.Println("    2) This computer + local network (adds passive device discovery)")
	fmt.Println("    q) Quit")
	fmt.Print("\n  Choose [1/2/q]: ")

	line, ok := readLine()
	if !ok {
		return scopeHost // no input available → safe default
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "2":
		return scopeNetwork
	case "q", "quit", "exit":
		return scopeQuit
	default: // "1", blank Enter, or anything else → host-only
		return scopeHost
	}
}

// askYesNo prompts and returns true only on an explicit yes. Defaults to no,
// including when no input is available.
func askYesNo(prompt string) bool {
	fmt.Print("  " + prompt)
	line, ok := readLine()
	if !ok {
		return false
	}
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "y" || a == "yes"
}

// defaultReportPath puts the report next to the executable (or CWD) with a
// timestamp so repeated runs don't overwrite each other.
func defaultReportPath() string {
	name := "bxb-posture-" + time.Now().Format("2006-01-02-150405") + ".html"
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), name)
	}
	return name
}

// readLine reads one line from stdin, returning ok=false if stdin is closed
// or unavailable (so non-interactive runs fall back to safe defaults).
func readLine() (string, bool) {
	line, err := stdin.ReadString('\n')
	if err != nil && line == "" {
		return "", false
	}
	return line, true
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
