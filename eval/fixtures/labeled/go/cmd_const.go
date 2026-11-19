package handlers

import (
	"net/http"
	"os/exec"
)

func Version(w http.ResponseWriter, r *http.Request) {
	out, _ := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	w.Write(out)
}
