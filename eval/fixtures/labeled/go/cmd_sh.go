package handlers

import (
	"net/http"
	"os/exec"
)

func Lookup(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, _ := exec.Command("sh", "-c", "nslookup "+host).Output()
	w.Write(out)
}
