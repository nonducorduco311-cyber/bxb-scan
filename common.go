package main

import (
	"context"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"time"
)

// run executes a command with a timeout and returns trimmed stdout.
// It never lets a slow/missing command hang the scan, and it never
// surfaces errors as fatal — a check that can't run just reports "unknown".
func run(name string, args ...string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

// runShell runs a shell pipeline (platform shell chosen by caller helpers).
func have(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// baseHostInfo fills the cross-platform parts; platform files refine OSName/Kernel.
func baseHostInfo() HostInfo {
	h := HostInfo{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}
	if hn, err := os.Hostname(); err == nil {
		h.Hostname = hn
	}
	if u, err := user.Current(); err == nil {
		h.User = u.Username
	}
	return h
}

// firstLine returns the first non-empty line of s.
func firstLine(s string) string {
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if ln != "" {
			return ln
		}
	}
	return ""
}

// containsFold is a case-insensitive substring test.
func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}
