//go:build !windows

package main

// pauseBeforeExit is a no-op on Linux/macOS, where the program runs in the
// user's own terminal.
func pauseBeforeExit(skip bool) {}
