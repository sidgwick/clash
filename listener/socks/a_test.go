package socks

import (
	"fmt"
	"testing"
)

func TestDuplicatePortConnections(t *testing.T) {
	addr := "127.0.0.1:11454"

	l1, err := New(addr, nil)
	if err != nil {
		panic(err)
	}

	l2, err := New(addr, nil)
	if err != nil {
		panic(err)
	}

	fmt.Printf("listen network created: %v, %v\n", l1, l2)
}
