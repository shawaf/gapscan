package handlers

import (
	"net/http"
	"os"
	"path/filepath"
)

func Download(w http.ResponseWriter, r *http.Request) {
	data, _ := os.ReadFile(filepath.Join("/srv/uploads", r.URL.Query().Get("file")))
	w.Write(data)
}
