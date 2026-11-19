package main

import (
	"fmt"
	"math/rand"
)

func newToken() string {
	return fmt.Sprintf("%016x%016x", rand.Int63(), rand.Int63()+int64(rand.Intn(1000)))
}
