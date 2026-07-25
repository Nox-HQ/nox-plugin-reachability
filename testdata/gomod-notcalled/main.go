// Package main imports net/url — the package the fixture advisory
// GO-9999-0001 names — but never calls the vulnerable symbol
// (PathEscape). This is the case reachability analysis exists for.
package main

import (
	"fmt"
	"net/url"
)

func main() {
	fmt.Println(url.QueryEscape("a b"))
}
