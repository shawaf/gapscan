package main

import (
	"archive/zip"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/tls"
	"database/sql"
	"fmt"
	"html/template"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var db *sql.DB

func sqlCases(name string) {
	// ruleid: gapscan.go.sqli-string-built
	db.Query("SELECT * FROM users WHERE name = '" + name + "'")
	// ruleid: gapscan.go.sqli-string-built
	db.Exec(fmt.Sprintf("DELETE FROM t WHERE id = %s", name))
	// ok: gapscan.go.sqli-string-built
	db.Query("SELECT * FROM users WHERE name = ?", name)
	// ok: gapscan.go.sqli-string-built
	db.Query("SELECT * FROM " + "users")
}

func commandCases(input string) {
	// ruleid: gapscan.go.command-via-shell
	exec.Command("sh", "-c", input).Run()
	// ruleid: gapscan.go.command-via-shell
	exec.Command("bash", "-c", "ping "+input).Run()
	// ok: gapscan.go.command-via-shell
	exec.Command("sh", "-c", "uptime").Run()
	// ok: gapscan.go.command-via-shell
	exec.Command("ping", "-c", "1", input).Run()
}

func cryptoCases(data []byte, key []byte) {
	// ruleid: gapscan.go.weak-hash
	md5.Sum(data)
	// ruleid: gapscan.go.weak-hash
	sha1.New()
	// ruleid: gapscan.go.weak-cipher
	des.NewCipher(key)
	// ruleid: gapscan.go.weak-cipher
	rc4.NewCipher(key)
}

func tlsCases() {
	// ruleid: gapscan.go.tls-verification-disabled
	_ = &tls.Config{InsecureSkipVerify: true}
	// ruleid: gapscan.go.tls-verification-disabled
	_ = &tls.Config{MinVersion: tls.VersionTLS10}
	// ok: gapscan.go.tls-verification-disabled
	_ = &tls.Config{MinVersion: tls.VersionTLS12}
}

// ruleid: gapscan.go.hardcoded-secret
const apiKey = "sk_live_51HxxxxxxxxxxxxxxxxYYY"

func secretCases() {
	// ruleid: gapscan.go.hardcoded-secret
	password := "hunter2hunter2"
	// ok: gapscan.go.hardcoded-secret
	password2 := os.Getenv("DB_PASSWORD")
	// ok: gapscan.go.hardcoded-secret
	token := ""
	_, _, _ = password, password2, token
}

func randomCases() {
	// ruleid: gapscan.go.insecure-random-token, gapscan.go.weak-random-generator
	resetToken := rand.Int63()
	// ruleid: gapscan.go.weak-random-generator
	roll := rand.Intn(6)
	_, _ = resetToken, roll
}

func urlCases() {
	// ruleid: gapscan.go.cleartext-http-url
	http.Get("http://example.com/api")
	// ok: gapscan.go.cleartext-http-url
	http.Get("https://example.com/api")
	// ok: gapscan.go.cleartext-http-url
	http.Get("http://localhost:8080/api")
}

func templateCases(user string) {
	// ruleid: gapscan.go.template-unescaped
	_ = template.HTML(user)
	// ok: gapscan.go.template-unescaped
	_ = template.HTML("<b>fixed</b>")
}

func cookieCases(w http.ResponseWriter) {
	// ruleid: gapscan.go.cookie-flags-off
	http.SetCookie(w, &http.Cookie{Name: "sid", Secure: false})
	// ok: gapscan.go.cookie-flags-off
	http.SetCookie(w, &http.Cookie{Name: "sid", Secure: true, HttpOnly: true})
}

func corsCases(w http.ResponseWriter) {
	// ruleid: gapscan.go.cors-allow-all
	w.Header().Set("Access-Control-Allow-Origin", "*")
	// ok: gapscan.go.cors-allow-all
	w.Header().Set("Access-Control-Allow-Origin", "https://app.example.com")
}

func permissionCases(path string, data []byte) {
	// ruleid: gapscan.go.file-permissions-too-open
	os.Chmod(path, 0777)
	// ok: gapscan.go.file-permissions-too-open
	os.WriteFile(path, data, 0600)
}

func jwtCases(t *jwt.Token) {
	// ruleid: gapscan.go.jwt-unsafe
	t.SignedString([]byte("supersecretvalue"))
	// ok: gapscan.go.jwt-unsafe
	t.SignedString(loadKey())
}

func zipCases(r *zip.Reader, dest string) {
	for _, f := range r.File {
		// ruleid: gapscan.go.zip-slip
		target := filepath.Join(dest, f.Name)
		_ = target
	}
	for _, f := range r.File {
		target := filepath.Join(dest, f.Name)
		// ok: gapscan.go.zip-slip
		if !strings.HasPrefix(target, dest) {
			continue
		}
	}
}

// =================== taint rules =============================================================================
func taintSQL(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	q := "SELECT * FROM users WHERE id = " + id
	// ruleid: gapscan.go.taint-sqli
	db.Query(q)
	// ok: gapscan.go.taint-sqli
	db.Query("SELECT * FROM users WHERE id = ?", id)
}

func taintGin(c *gin.Context) {
	id := c.Param("id")
	// ruleid: gapscan.go.sqli-string-built, gapscan.go.taint-sqli
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))
}

func taintCmd(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	// ruleid: gapscan.go.command-via-shell, gapscan.go.taint-command-injection
	exec.Command("sh", "-c", "ping "+host).Run()
	// ok: gapscan.go.taint-command-injection
	exec.Command("ping", "-c", "1", host).Run()
}

func taintPath(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	p := filepath.Join("/var/uploads", name)
	// ruleid: gapscan.go.taint-path-traversal
	data, _ := os.ReadFile(p)
	w.Write(data)
}

func taintPathSafe(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Query().Get("name"))
	// ok: gapscan.go.taint-path-traversal
	data, _ := os.ReadFile(filepath.Join("/var/uploads", name))
	w.Write(data)
}

func taintSSRF(w http.ResponseWriter, r *http.Request) {
	target := r.Header.Get("X-Forward-URL")
	// ruleid: gapscan.go.taint-ssrf
	resp, _ := http.Get(target)
	defer resp.Body.Close()
	// ok: gapscan.go.taint-ssrf
	http.Get("https://api.example.com/status")
}

func taintXSS(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	// ruleid: gapscan.go.taint-xss
	fmt.Fprintf(w, "<p>You searched: %s</p>", q)
	// ruleid: gapscan.go.taint-xss
	io.WriteString(w, q)
}

func taintXSSSafe(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	// ok: gapscan.go.taint-xss
	fmt.Fprintf(w, "<p>%s</p>", template.HTMLEscapeString(q))
}

func taintRedirect(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	// ruleid: gapscan.go.taint-open-redirect
	http.Redirect(w, r, next, http.StatusFound)
	// ok: gapscan.go.taint-open-redirect
	http.Redirect(w, r, "/home", http.StatusFound)
}

func taintTemplate(w http.ResponseWriter, r *http.Request) {
	tpl := r.FormValue("t")
	// ruleid: gapscan.go.taint-template-injection
	template.New("x").Parse(tpl)
	// ok: gapscan.go.taint-template-injection
	template.New("x").Parse("Hello {{.Name}}")
}
