//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
)

// pauseBeforeExit holds the console window open so a double-click launch is
// readable. Always pauses unless the user passed --no-pause.
func pauseBeforeExit(skip bool) {
	if skip {
		return
	}
	fmt.Print("\nScan complete. Press Enter to close this window...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
