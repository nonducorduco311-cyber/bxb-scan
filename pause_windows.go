//go:build windows

package main

import "fmt"

// pauseBeforeExit holds the console window open so a double-click launch is
// readable. Always pauses unless the user passed --no-pause. Uses the shared
// stdin reader so buffered input from earlier prompts isn't lost.
func pauseBeforeExit(skip bool) {
	if skip {
		return
	}
	fmt.Print("\nScan complete. Press Enter to close this window...")
	stdin.ReadString('\n')
}
