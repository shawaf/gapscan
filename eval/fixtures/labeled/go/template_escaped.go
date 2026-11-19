package main

import (
	"html/template"
	"net/http"
)

var page = template.Must(template.New("p").Parse("<div>{{.}}</div>"))

func hello(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	page.Execute(w, name)
}
