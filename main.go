package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	para "github.com/fumiama/go-hide-param"
	tea "github.com/fumiama/gofastTEA"
)

var mytea tea.TEA

// usage: -l ip:port -k authkeyhex -p /route1=/path1 -s /route2=/path2 ...
func main() {
	paths := make(map[string]string)
	spaths := make(map[string]string)
	ipport := ""

	isnextpath := false
	isnextsecurepath := false
	isnextipport := false
	isnexttea := false
	for i, s := range os.Args {
		switch {
		case isnextpath:
			isnextpath = false
			pair := strings.Split(s, "=")
			if len(pair) != 2 {
				panic("wrong pair syntax")
			}
			paths[pair[0]] = pair[1]
		case isnextsecurepath:
			isnextsecurepath = false
			pair := strings.Split(s, "=")
			if len(pair) != 2 {
				panic("wrong pair syntax")
			}
			spaths[pair[0]] = pair[1]
		case isnextipport:
			isnextipport = false
			ipport = s
		case isnexttea:
			isnexttea = false
			if len(s) != 32 {
				panic("auth key must be 16 bytes")
			}
			data, err := hex.DecodeString(s)
			if err != nil {
				panic(err)
			}
			mytea = tea.NewTeaCipherLittleEndian(data)
			para.Hide(i)
		case s == "-p":
			isnextpath = true
		case s == "-s":
			isnextsecurepath = true
		case s == "-l":
			isnextipport = true
		case s == "-k":
			isnexttea = true
		}
	}

	listener, err := net.Listen("tcp", ipport)
	if err != nil {
		panic(err)
	}

	for r, p := range paths {
		err = handle(r, p, false)
		if err != nil {
			panic(err)
		}
	}
	for r, p := range spaths {
		err = handle(r, p, true)
		if err != nil {
			panic(err)
		}
	}

	fmt.Println("start serving on", ipport)
	fmt.Println(http.Serve(listener, nil))
}
