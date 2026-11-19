package main

import (
	"crypto/rand"
	"encoding/hex"
)

func newToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}
