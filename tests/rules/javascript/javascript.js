const crypto = require("crypto");
const child_process = require("child_process");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const express = require("express");
const app = express();

// --- sqli-string-built ---------------------------------------------------------------------------
function sqlCases(db, name, id) {
  // ruleid: gapscan.javascript.sqli-string-built
  db.query("SELECT * FROM users WHERE name = '" + name + "'");
  // ruleid: gapscan.javascript.sqli-string-built
  db.query(`SELECT * FROM users WHERE id = ${id}`);
  // ruleid: gapscan.javascript.sqli-string-built
  db.execute("DELETE FROM t WHERE id = " + id);
  // ok: gapscan.javascript.sqli-string-built
  db.query("SELECT * FROM users WHERE id = $1", [id]);
  // ok: gapscan.javascript.sqli-string-built
  db.query("SELECT * FROM users " + "WHERE active = 1");
  // ok: gapscan.javascript.sqli-string-built
  cache.get(`user:${id}`);
}

// --- command-injection ------------------------------------------------------------------------
function commandCases(host) {
  // ruleid: gapscan.javascript.command-injection
  child_process.exec("ping -c 1 " + host);
  // ruleid: gapscan.javascript.command-injection
  child_process.execSync(`nslookup ${host}`);
  // ok: gapscan.javascript.command-injection
  child_process.exec("uptime");
  // ok: gapscan.javascript.command-injection
  child_process.execFile("ping", ["-c", "1", host]);
  // ok: gapscan.javascript.command-injection
  /a(b)/.exec(host);
}

// --- code-injection -----------------------------------------------------------------------------
function codeCases(expr) {
  // ruleid: gapscan.javascript.code-injection
  eval(expr);
  // ruleid: gapscan.javascript.code-injection
  new Function("a", expr);
  // ruleid: gapscan.javascript.code-injection
  setTimeout("run(" + expr + ")", 10);
  // ok: gapscan.javascript.code-injection
  eval("1 + 1");
  // ok: gapscan.javascript.code-injection
  setTimeout(() => run(expr), 10);
}

// --- dom-xss --------------------------------------------------------------------------------------
function domCases(el, userText, $) {
  // ruleid: gapscan.javascript.dom-xss
  el.innerHTML = userText;
  // ruleid: gapscan.javascript.dom-xss
  document.write("<p>" + userText + "</p>");
  // ruleid: gapscan.javascript.dom-xss
  el.insertAdjacentHTML("beforeend", userText);
  // ruleid: gapscan.javascript.dom-xss
  $("#out").html(userText);
  // ok: gapscan.javascript.dom-xss
  el.textContent = userText;
  // ok: gapscan.javascript.dom-xss
  el.innerHTML = "<b>fixed</b>";
  // ok: gapscan.javascript.dom-xss
  el.innerHTML = DOMPurify.sanitize(userText);
  // ok: gapscan.javascript.dom-xss
  $("#out").text(userText);
}

function Comment({ body }) {
  // ruleid: gapscan.javascript.dom-xss
  return <div dangerouslySetInnerHTML={{ __html: body }} />;
}

function SafeComment({ body }) {
  // ok: gapscan.javascript.dom-xss
  return <div>{body}</div>;
}

// --- tls-verification-disabled -----------------------------------------------------------------------
// ruleid: gapscan.javascript.tls-verification-disabled
const agent = new https.Agent({ rejectUnauthorized: false });
// ruleid: gapscan.javascript.tls-verification-disabled
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
// ok: gapscan.javascript.tls-verification-disabled
const agent2 = new https.Agent({ rejectUnauthorized: true });

// --- weak-hash --------------------------------------------------------------------------------------------
function hashCases(data) {
  // ruleid: gapscan.javascript.weak-hash
  crypto.createHash("md5").update(data);
  // ruleid: gapscan.javascript.weak-hash
  crypto.createHash("sha1").update(data);
  // ok: gapscan.javascript.weak-hash
  crypto.createHash("sha256").update(data);
}

// --- weak-cipher -------------------------------------------------------------------------------------------
function cipherCases(key, iv) {
  // ruleid: gapscan.javascript.weak-cipher
  crypto.createCipher("aes-256-cbc", key);
  // ruleid: gapscan.javascript.weak-cipher
  crypto.createCipheriv("des-ede3", key, iv);
  // ruleid: gapscan.javascript.weak-cipher
  crypto.createCipheriv("aes-128-ecb", key, null);
  // ok: gapscan.javascript.weak-cipher
  crypto.createCipheriv("aes-256-gcm", key, iv);
}

// --- jwt-unsafe -----------------------------------------------------------------------------------------------
function jwtCases(token, payload) {
  // ruleid: gapscan.javascript.jwt-unsafe
  jwt.sign(payload, "supersecretvalue");
  // ruleid: gapscan.javascript.jwt-unsafe
  jwt.verify(token, process.env.KEY, { algorithms: ["none"] });
  // ok: gapscan.javascript.jwt-unsafe
  jwt.sign(payload, process.env.JWT_SECRET);
  // ok: gapscan.javascript.jwt-unsafe
  jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256"] });
}

// --- jwt-decode-not-verified ---------------------------------------------------------------------------------------
function decodeCases(token) {
  // ruleid: gapscan.javascript.jwt-decode-not-verified
  const claims = jwt.decode(token);
  // ok: gapscan.javascript.jwt-decode-not-verified
  const verified = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256"] });
  return [claims, verified];
}

// --- hardcoded-secret ------------------------------------------------------------------------------------------
// ruleid: gapscan.javascript.hardcoded-secret
const password = "hunter2hunter2";
// ruleid: gapscan.javascript.hardcoded-secret
const apiKey = "sk_live_51HxxxxxxxxxxxxxxxxYYY";
// ruleid: gapscan.javascript.hardcoded-secret
const config = { secret: "correct-horse-battery" };
// ok: gapscan.javascript.hardcoded-secret
const password2 = process.env.DB_PASSWORD;
// ok: gapscan.javascript.hardcoded-secret
const token = "";
// ok: gapscan.javascript.hardcoded-secret
const config2 = { secret: "changeme" };
// ok: gapscan.javascript.hardcoded-secret
const passwordField = "password";

// --- insecure-random-token ---------------------------------------------------------------------------------------
function randomCases() {
  // ruleid: gapscan.javascript.insecure-random-token
  const resetToken = Math.random().toString(36).slice(2);
  // ruleid: gapscan.javascript.insecure-random-token
  const otp = Math.floor(Math.random() * 1000000);
  // ok: gapscan.javascript.insecure-random-token
  const resetToken2 = crypto.randomBytes(32).toString("hex");
  // ok: gapscan.javascript.insecure-random-token
  const colour = Math.random();
  return [resetToken, otp, resetToken2, colour];
}

// --- cookie-flags-off -----------------------------------------------------------------------------------------------
// ruleid: gapscan.javascript.cookie-flags-off
app.use(session({ secret: process.env.S, cookie: { secure: false } }));
// ruleid: gapscan.javascript.cookie-flags-off
app.get("/c", (req, res) => res.cookie("sid", "x", { httpOnly: false }));
// ok: gapscan.javascript.cookie-flags-off
app.use(session({ secret: process.env.S, cookie: { secure: true, httpOnly: true } }));

// --- cors-allow-all -----------------------------------------------------------------------------------------------------
// ruleid: gapscan.javascript.cors-allow-all
app.use(cors({ origin: "*" }));
// ruleid: gapscan.javascript.cors-allow-all
app.use((req, res, next) => { res.setHeader("Access-Control-Allow-Origin", "*"); next(); });
// ruleid: gapscan.javascript.cors-allow-all
app.use((req, res, next) => { res.setHeader("Access-Control-Allow-Origin", req.headers.origin); next(); });
// ok: gapscan.javascript.cors-allow-all
app.use(cors({ origin: "https://app.example.com" }));

// --- unsafe-deserialization -------------------------------------------------------------------------------------------------
function deserializeCases(serialize, blob) {
  // ruleid: gapscan.javascript.unsafe-deserialization
  serialize.unserialize(blob);
  // ok: gapscan.javascript.unsafe-deserialization
  JSON.parse(blob);
}

// --- postmessage-any-origin ----------------------------------------------------------------------------------------------------
function postCases(win, data) {
  // ruleid: gapscan.javascript.postmessage-any-origin
  win.postMessage(data, "*");
  // ok: gapscan.javascript.postmessage-any-origin
  win.postMessage(data, "https://app.example.com");
}

// =================== taint rules ======================================================================================
app.get("/user", (req, res) => {
  const q = "SELECT * FROM users WHERE id = " + req.query.id;
  // ruleid: gapscan.javascript.taint-sqli
  db.query(q);
  const safeId = parseInt(req.query.id);
  const q2 = "SELECT * FROM users WHERE id = " + safeId;
  // ok: gapscan.javascript.taint-sqli
  db.query(q2);
  // ok: gapscan.javascript.taint-sqli
  db.query("SELECT * FROM users WHERE id = $1", [req.query.id]);
});

app.get("/ping", (req, res) => {
  const cmd = "ping -c 1 " + req.query.host;
  // ruleid: gapscan.javascript.command-injection, gapscan.javascript.taint-command-injection
  child_process.exec(cmd);
  // ok: gapscan.javascript.taint-command-injection
  child_process.execFile("ping", ["-c", "1", req.query.host]);
});

app.get("/file", (req, res) => {
  const p = "/srv/files/" + req.query.name;
  // ruleid: gapscan.javascript.taint-path-traversal
  fs.readFile(p, (err, data) => res.send(data));
});

app.get("/file2", (req, res) => {
  const p = "/srv/files/" + path.basename(req.query.name);
  // ok: gapscan.javascript.taint-path-traversal
  fs.readFile(p, (err, data) => res.send(data));
});

app.get("/fetch", async (req, res) => {
  const target = req.query.url;
  // ruleid: gapscan.javascript.taint-ssrf
  const r = await axios.get(target);
  // ruleid: gapscan.javascript.taint-xss
  res.send(r.data);
});

app.get("/fixed", async (req, res) => {
  // ok: gapscan.javascript.taint-ssrf
  const r = await axios.get("https://api.example.com/status");
  res.send(r.data);
});

app.get("/go", (req, res) => {
  const next = req.query.next;
  // ruleid: gapscan.javascript.taint-open-redirect
  res.redirect(next);
});

app.get("/go2", (req, res) => {
  // ok: gapscan.javascript.taint-open-redirect
  res.redirect("/home");
});

app.get("/calc", (req, res) => {
  const expr = req.query.expr;
  // ruleid: gapscan.javascript.code-injection, gapscan.javascript.taint-code-injection, gapscan.javascript.taint-xss
  res.send(String(eval(expr)));
});

app.post("/login", async (req, res) => {
  const filter = { name: req.body.name, pass: req.body.pass };
  // ruleid: gapscan.javascript.taint-nosql-injection
  const u = await User.findOne(filter);
  // ok: gapscan.javascript.taint-nosql-injection
  const v = await User.findOne({ name: String(req.body.name) });
  res.send([u, v]);
});

function domTaint(el) {
  const hash = location.hash;
  // ruleid: gapscan.javascript.dom-xss, gapscan.javascript.taint-dom-xss
  el.innerHTML = hash;
  // ok: gapscan.javascript.taint-dom-xss
  el.textContent = location.hash;
}

// =================== round 1 additions ===================================================================================
function angularCases(sanitizer, userText) {
  // ruleid: gapscan.javascript.angular-sanitizer-bypass
  sanitizer.bypassSecurityTrustHtml(userText);
  // ok: gapscan.javascript.angular-sanitizer-bypass
  sanitizer.bypassSecurityTrustHtml("<b>fixed</b>");
}

function whereCases(coll, threshold) {
  // ruleid: gapscan.javascript.nosql-where-string-built
  coll.find({ $where: "this.stocks > " + threshold });
  // ok: gapscan.javascript.nosql-where-string-built
  coll.find({ stocks: { $gt: Number(threshold) } });
}

app.get("/search", (req, res) => {
  const q = req.query.q;
  // ruleid: gapscan.javascript.taint-xss
  res.send("<h1>Results for: " + q + "</h1>");
});

app.get("/search2", (req, res) => {
  const q = req.query.q;
  // ok: gapscan.javascript.taint-xss
  res.send("<h1>Results for: " + escapeHtml(q) + "</h1>");
  // ok: gapscan.javascript.taint-xss
  res.send({ q: q });
});

app.get("/other", (request, response) => {
  const url = request.query.url + request.query.symbol;
  // ruleid: gapscan.javascript.taint-ssrf
  needle.get(url, (error, body) => response.json(body));
});

function domTaintAngular(route, sanitizer) {
  const q = route.snapshot.queryParams.q;
  // ruleid: gapscan.javascript.angular-sanitizer-bypass, gapscan.javascript.taint-dom-xss
  sanitizer.bypassSecurityTrustResourceUrl(q);
}
