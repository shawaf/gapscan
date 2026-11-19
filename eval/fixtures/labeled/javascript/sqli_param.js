const express = require("express");
const db = require("./db");
const app = express();

app.get("/users", (req, res) => {
  db.query("SELECT id, email FROM users WHERE name = ?", [req.query.name], (err, rows) => {
    res.json(rows);
  });
});
