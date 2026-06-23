//go:build !windows

package main

// On Linux/macOS the program runs in the terminal the user invoked it from,
// so there is no vanishing-window problem and no need to pause.
func launchedByDoubleClick() bool { return false }
