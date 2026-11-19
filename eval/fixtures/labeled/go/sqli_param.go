package handlers

import (
	"database/sql"
	"net/http"
)

func Users(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	rows, _ := db.Query("SELECT id, email FROM users WHERE name = ?", r.URL.Query().Get("name"))
	defer rows.Close()
}
