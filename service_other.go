//go:build !windows && !darwin

package main

func runService([]string) (int, bool) { return 0, false }
