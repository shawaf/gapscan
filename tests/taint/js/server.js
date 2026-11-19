const express = require("express");
const cp = require("child_process");
const fs = require("fs");
const db = require("./db");
const { render, joinPath } = require("./helpers");
const app = express();

app.get("/user", (req, res) => {
  const name = req.query.name;
  db.query("SELECT * FROM users WHERE name = '" + name + "'"); // VULN:sql
  db.query("SELECT * FROM users WHERE id = $1", [name]); // SAFE
  res.send("ok");
});

app.get("/user2", (req, res) => {
  const id = parseInt(req.query.id, 10); // SAFE-FLOW
  db.query("SELECT * FROM users WHERE id = " + id); // SAFE
  res.send("ok");
});

app.get("/ping", (req, res) => {
  cp.exec("ping -c1 " + req.query.host); // VULN:cmd
  cp.exec("ping -c1 localhost"); // SAFE
  res.send("ok");
});

app.get("/file", (req, res) => {
  const p = joinPath("/srv", req.query.f);
  fs.readFile(p, () => {}); // VULN:path
  res.send("ok");
});

app.get("/file2", (req, res) => {
  const p = joinPath("/srv", "fixed.txt");
  fs.readFile(p, () => {}); // SAFE
  res.send("ok");
});

app.get("/hello", (req, res) => {
  res.send(render(req.query.who)); // VULN:xss
});

app.get("/hello2", (req, res) => {
  res.send(render("world")); // SAFE
});

app.get("/go", (req, res) => {
  res.redirect(req.query.next); // VULN:redirect
});

app.get("/calc", (req, res) => {
  const out = eval(req.body.expr); // VULN:code
  res.send(String(out)); // VULN:xss
});

app.post("/body", (req, res) => {
  const { cmd } = req.body;
  cp.execSync(cmd); // VULN:cmd
  const x = "constant";
  cp.execSync(x); // SAFE
});

app.get("/dom", (req, res) => {
  const el = {};
  el.innerHTML = req.query.html; // VULN:xss
  el.innerHTML = "<b>static</b>"; // SAFE
  res.send("ok");
});
