"""More backend and frontend cases (Python, JavaScript, Java, Go): XXE, open redirect, TLS
verification, JWT, archive extraction, template injection, CORS, cookies, insecure randomness,
HTML escaping. Each has a vulnerable site and a safe look-alike."""

from __future__ import annotations

from collections.abc import Callable

A01, A02, A04, A05, A07 = "A01:2025", "A02:2025", "A04:2025", "A05:2025", "A07:2025"


def register(case: Callable[..., None]) -> None:
    # ---------------------------------------------------------------------------- Python
    case(
        "py-xxe-lxml",
        "python/xxe_lxml.py",
        "etree.fromstring(",
        "CWE-611",
        A02,
        True,
        """
from flask import Flask, request
from lxml import etree

app = Flask(__name__)


@app.route("/import", methods=["POST"])
def import_xml():
    parser = etree.XMLParser(resolve_entities=True, load_dtd=True)
    doc = etree.fromstring(request.get_data(), parser)
    return {"root": doc.tag}
""",
    )
    case(
        "py-xxe-defused",
        "python/xxe_defused.py",
        "fromstring(",
        "CWE-611",
        A02,
        False,
        """
from defusedxml.ElementTree import fromstring
from flask import Flask, request

app = Flask(__name__)


@app.route("/import", methods=["POST"])
def import_xml():
    doc = fromstring(request.get_data())
    return {"root": doc.tag}
""",
    )
    case(
        "py-redirect-open",
        "python/redirect_open.py",
        "redirect(",
        "CWE-601",
        A01,
        True,
        """
from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/login/done")
def done():
    return redirect(request.args.get("next", "/"))
""",
    )
    case(
        "py-redirect-allowlist",
        "python/redirect_allowlist.py",
        "redirect(",
        "CWE-601",
        A01,
        False,
        """
from flask import Flask, redirect, request

app = Flask(__name__)
PAGES = {"home": "/", "account": "/account", "billing": "/billing"}


@app.route("/login/done")
def done():
    target = PAGES.get(request.args.get("next", ""), "/")
    return redirect(target)
""",
    )
    case(
        "py-tls-verify-off",
        "python/tls_verify_off.py",
        "requests.get(",
        "CWE-295",
        A04,
        True,
        """
import requests


def fetch_report(url: str) -> bytes:
    return requests.get(url, verify=False, timeout=10).content
""",
    )
    case(
        "py-tls-verify-on",
        "python/tls_verify_on.py",
        "requests.get(",
        "CWE-295",
        A04,
        False,
        """
import requests


def fetch_report(url: str) -> bytes:
    return requests.get(url, timeout=10).content
""",
    )
    case(
        "py-jwt-no-verify",
        "python/jwt_no_verify.py",
        "jwt.decode(",
        "CWE-347",
        A07,
        True,
        """
import jwt
from flask import Flask, request

app = Flask(__name__)


@app.route("/me")
def me():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    claims = jwt.decode(token, options={"verify_signature": False})
    return {"user": claims.get("sub")}
""",
    )
    case(
        "py-jwt-verified",
        "python/jwt_verified.py",
        "jwt.decode(",
        "CWE-347",
        A07,
        False,
        """
import os

import jwt
from flask import Flask, abort, request

app = Flask(__name__)
SECRET = os.environ["JWT_SECRET"]


@app.route("/me")
def me():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    try:
        claims = jwt.decode(token, SECRET, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        abort(401)
    return {"user": claims.get("sub")}
""",
    )
    case(
        "py-zipslip",
        "python/zipslip.py",
        "extractall(",
        "CWE-22",
        A01,
        True,
        """
import zipfile

from flask import Flask, request

app = Flask(__name__)


@app.route("/upload", methods=["POST"])
def upload():
    with open("/tmp/in.zip", "wb") as fh:
        fh.write(request.get_data())
    with zipfile.ZipFile("/tmp/in.zip") as zf:
        zf.extractall("/srv/uploads")
    return "ok"
""",
    )
    case(
        "py-zip-checked",
        "python/zip_checked.py",
        "zf.extract(",
        "CWE-22",
        A01,
        False,
        """
import os
import zipfile

DEST = os.path.realpath("/srv/uploads")


def unpack(path: str) -> None:
    with zipfile.ZipFile(path) as zf:
        for name in zf.namelist():
            target = os.path.realpath(os.path.join(DEST, name))
            if not target.startswith(DEST + os.sep):
                raise ValueError("unsafe archive member")
            zf.extract(name, DEST)
""",
    )
    case(
        "py-ssti",
        "python/ssti.py",
        "render_template_string(",
        "CWE-1336",
        A05,
        True,
        """
from flask import Flask, render_template_string, request

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "friend")
    return render_template_string("<h1>Hello " + name + "</h1>")
""",
    )
    case(
        "py-template-context",
        "python/template_context.py",
        "render_template_string(",
        "CWE-1336",
        A05,
        False,
        """
from flask import Flask, render_template_string, request

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "friend")
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)
""",
    )

    # ------------------------------------------------------------------------ JavaScript
    case(
        "js-jwt-decode-only",
        "javascript/jwt_decode_only.js",
        "jwt.decode(",
        "CWE-347",
        A07,
        True,
        """
const jwt = require("jsonwebtoken");

function currentUser(req) {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  const claims = jwt.decode(token);
  return claims && claims.sub;
}

module.exports = { currentUser };
""",
    )
    case(
        "js-jwt-verify",
        "javascript/jwt_verify.js",
        "jwt.verify(",
        "CWE-347",
        A07,
        False,
        """
const jwt = require("jsonwebtoken");

function currentUser(req) {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  try {
    return jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256"] }).sub;
  } catch (err) {
    return null;
  }
}

module.exports = { currentUser };
""",
    )
    case(
        "js-cors-reflect",
        "javascript/cors_reflect.js",
        "Access-Control-Allow-Origin",
        "CWE-942",
        A02,
        True,
        """
const express = require("express");
const app = express();

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  next();
});

app.get("/api/profile", (req, res) => res.json({ user: req.user }));
""",
    )
    case(
        "js-cors-allowlist",
        "javascript/cors_allowlist.js",
        "Access-Control-Allow-Origin",
        "CWE-942",
        A02,
        False,
        """
const express = require("express");
const app = express();
const ALLOWED = new Set(["https://app.example.com", "https://admin.example.com"]);

app.use((req, res, next) => {
  if (ALLOWED.has(req.headers.origin)) {
    res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  next();
});

app.get("/api/profile", (req, res) => res.json({ user: req.user }));
""",
    )
    case(
        "js-cookie-insecure",
        "javascript/cookie_insecure.js",
        "cookie:",
        "CWE-614",
        A02,
        True,
        """
const express = require("express");
const session = require("express-session");
const app = express();

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: false },
}));
""",
    )
    case(
        "js-cookie-hardened",
        "javascript/cookie_hardened.js",
        "cookie:",
        "CWE-614",
        A02,
        False,
        """
const express = require("express");
const session = require("express-session");
const app = express();

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: true, httpOnly: true, sameSite: "lax" },
}));
""",
    )

    # --------------------------------------------------------------------------- Java
    case(
        "java-xxe-dbf",
        "java/XxeDbf.java",
        "newDocumentBuilder()",
        "CWE-611",
        A02,
        True,
        """
import java.io.InputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public class XxeDbf {
    public Document parse(InputStream body) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(body);
    }
}
""",
    )
    case(
        "java-xxe-hardened",
        "java/XxeHardened.java",
        "newDocumentBuilder()",
        "CWE-611",
        A02,
        False,
        """
import java.io.InputStream;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public class XxeHardened {
    public Document parse(InputStream body) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(body);
    }
}
""",
    )
    case(
        "java-hostname-all",
        "java/HostnameAll.java",
        "HostnameVerifier",
        "CWE-295",
        A04,
        True,
        """
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.HostnameVerifier;

public class HostnameAll {
    public void install() {
        HostnameVerifier allowAll = (hostname, session) -> true;
        HttpsURLConnection.setDefaultHostnameVerifier(allowAll);
    }
}
""",
    )
    case(
        "java-https-default",
        "java/HttpsDefault.java",
        "openConnection()",
        "CWE-295",
        A04,
        False,
        """
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;

public class HttpsDefault {
    public int status(String host) throws Exception {
        URL url = new URL("https://" + host + "/health");
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        return conn.getResponseCode();
    }
}
""",
    )

    # ----------------------------------------------------------------------------- Go
    case(
        "go-tls-skip-verify",
        "go/tls_skip_verify.go",
        "InsecureSkipVerify",
        "CWE-295",
        A04,
        True,
        """
package main

import (
	"crypto/tls"
	"net/http"
)

func client() *http.Client {
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
}
""",
    )
    case(
        "go-tls-default",
        "go/tls_default.go",
        "http.Client{",
        "CWE-295",
        A04,
        False,
        """
package main

import (
	"net/http"
	"time"
)

func client() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}
""",
    )
    case(
        "go-template-html",
        "go/template_html.go",
        "template.HTML(",
        "CWE-79",
        A05,
        True,
        """
package main

import (
	"html/template"
	"net/http"
)

var page = template.Must(template.New("p").Parse("<div>{{.}}</div>"))

func hello(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	page.Execute(w, template.HTML(name))
}
""",
    )
    case(
        "go-template-escaped",
        "go/template_escaped.go",
        "page.Execute(",
        "CWE-79",
        A05,
        False,
        """
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
""",
    )
    case(
        "go-math-rand-token",
        "go/math_rand_token.go",
        "rand.Intn(",
        "CWE-338",
        A04,
        True,
        """
package main

import (
	"fmt"
	"math/rand"
)

func newToken() string {
	return fmt.Sprintf("%016x%016x", rand.Int63(), rand.Int63()+int64(rand.Intn(1000)))
}
""",
    )
    case(
        "go-crypto-rand-token",
        "go/crypto_rand_token.go",
        "rand.Read(",
        "CWE-338",
        A04,
        False,
        """
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
""",
    )
