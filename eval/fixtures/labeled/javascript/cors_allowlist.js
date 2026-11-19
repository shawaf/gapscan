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
