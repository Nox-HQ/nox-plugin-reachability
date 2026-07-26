// Package main calls the symbol named by the fixture advisory
// GO-9999-0001, so govulncheck must report a symbol-level trace.
package main

import (
	"fmt"
	"net/url"
)

func main() {
	fmt.Println(url.PathEscape("a b"))
}
