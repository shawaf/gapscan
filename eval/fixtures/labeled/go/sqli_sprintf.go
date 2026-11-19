package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
)

func Users(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, _ := db.Query(fmt.Sprintf("SELECT id, email FROM users WHERE name = '%s'", name))
	defer rows.Close()
}
