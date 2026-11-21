//go:build !linux

package main

import (
	"fmt"
	"os"
)

// main refuses: guestinit is the /init of a Linux guest initrd and does
// nothing elsewhere.
func main() {
	fmt.Fprintln(os.Stderr, "guestinit: runs only as /init of the kit's Linux guest")
	os.Exit(2)
}
