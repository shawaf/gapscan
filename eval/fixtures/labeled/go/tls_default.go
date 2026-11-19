package main

import (
	"net/http"
	"time"
)

func client() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}
