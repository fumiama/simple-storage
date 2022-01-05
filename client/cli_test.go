package client

import (
	"os"
	"testing"
)

func TestSet(t *testing.T) {
	cli := NewClient("http://127.0.0.1:8888", "00010203040506070809000102030405")
	if cli == nil {
		t.Fatal("cli is nil")
	}
	data, err := os.ReadFile("data/37774037_0.jpeg")
	if err != nil {
		t.Fatal(err)
	}
	err = cli.SetFile("data", "37774037_0.jpeg", data)
	if err != nil {
		t.Fatal(err)
	}
}
